import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { findConnection, loadConfig, validateLocalPath } from "./config.js";
import { chmodSocketPath, DEFAULT_CACHE_TTL_MS, normalizeCacheTtl, unlinkSocketPath } from "./daemon-paths.js";
import {
  connectSshClient,
  downloadFileWithClient,
  executeRemoteCommandWithClient,
  uploadFileWithClient,
  validateCommand
} from "./ssh-client.js";

const connections = new Map();
let activeRequests = 0;
let lastActivityAt = Date.now();
let exitTimer;
let server;
let socketPath;
let boundConfigPath;
let daemonToken;

function parseArgs(argv) {
  const socketIndex = argv.indexOf("--socket");
  const configIndex = argv.indexOf("--config");
  const tokenFileIndex = argv.indexOf("--token-file");
  const parsedSocketPath = socketIndex === -1 ? undefined : argv[socketIndex + 1];
  const configPath = configIndex === -1 ? undefined : argv[configIndex + 1];
  const tokenFilePath = tokenFileIndex === -1 ? undefined : argv[tokenFileIndex + 1];
  if (!parsedSocketPath) {
    throw new Error("daemon 缺少 --socket 参数");
  }
  if (!configPath) {
    throw new Error("daemon 缺少 --config 参数");
  }
  if (!tokenFilePath) {
    throw new Error("daemon 缺少 --token-file 参数");
  }
  return {
    socketPath: parsedSocketPath,
    configPath: path.resolve(configPath),
    tokenFilePath: path.resolve(tokenFilePath)
  };
}

function writeResponse(socket, response) {
  socket.write(`${JSON.stringify(response)}\n`, () => socket.end());
}

function buildConnectionKey(configPath, connection) {
  const auth = connection.agent
    ? { type: "agent", value: connection.agent }
    : connection.privateKey
      ? { type: "privateKey", value: connection.privateKey, passphrase: connection.passphrase }
      : { type: "password", value: connection.password };
  const raw = JSON.stringify({
    configPath: path.resolve(configPath),
    name: connection.name,
    host: connection.host,
    port: connection.port,
    username: connection.username,
    socksProxy: connection.socksProxy,
    auth
  });
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function removeEntry(key) {
  const entry = connections.get(key);
  if (!entry) {
    return;
  }
  connections.delete(key);
  if (entry.client) {
    entry.client.end();
  }
}

function scheduleExitCheck() {
  clearTimeout(exitTimer);
  if (activeRequests > 0) {
    return;
  }
  const now = Date.now();
  let waitMs = DEFAULT_CACHE_TTL_MS;
  if (connections.size === 0) {
    waitMs = Math.max(100, DEFAULT_CACHE_TTL_MS - (now - lastActivityAt));
  }
  for (const entry of connections.values()) {
    waitMs = Math.min(waitMs, Math.max(100, entry.ttlMs - (now - entry.lastUsedAt)));
  }
  exitTimer = setTimeout(() => {
    if (activeRequests > 0) {
      scheduleExitCheck();
      return;
    }
    const checkedAt = Date.now();
    for (const [key, entry] of connections.entries()) {
      if (checkedAt - entry.lastUsedAt >= entry.ttlMs) {
        removeEntry(key);
      }
    }
    if (connections.size === 0 && checkedAt - lastActivityAt >= DEFAULT_CACHE_TTL_MS) {
      shutdown();
      return;
    }
    if (connections.size === 0) {
      shutdown();
      return;
    }
    scheduleExitCheck();
  }, waitMs);
}

async function getPoolEntry(configPath, connection, ttlMs) {
  const key = buildConnectionKey(configPath, connection);
  let entry = connections.get(key);
  if (!entry) {
    entry = {
      key,
      client: undefined,
      clientPromise: undefined,
      queue: Promise.resolve(),
      lastUsedAt: Date.now(),
      ttlMs
    };
    entry.clientPromise = connectSshClient(connection)
      .then((client) => {
        entry.client = client;
        client.on("error", () => removeEntry(key));
        client.on("close", () => removeEntry(key));
        return client;
      })
      .catch((error) => {
        connections.delete(key);
        throw error;
      });
    connections.set(key, entry);
  }
  entry.ttlMs = ttlMs;
  entry.lastUsedAt = Date.now();
  await entry.clientPromise;
  return entry;
}

async function runSerialized(entry, operation) {
  const run = async () => {
    const client = await entry.clientPromise;
    return operation(client);
  };
  const resultPromise = entry.queue.then(run, run);
  entry.queue = resultPromise.catch(() => undefined);
  return resultPromise;
}

async function executeRequest(request) {
  if (request.token !== daemonToken) {
    throw new Error("SSH 缓存进程认证失败");
  }
  const requestConfigPath = path.resolve(request.configPath);
  if (requestConfigPath !== boundConfigPath) {
    throw new Error("SSH 缓存进程拒绝访问非绑定配置文件");
  }
  const ttlMs = normalizeCacheTtl(request.cacheTtlMs);
  const configs = loadConfig(boundConfigPath);
  const connection = findConnection(configs, request.connectionName);
  if (request.operation === "execute") {
    validateCommand(connection, request.command);
  }
  const entry = await getPoolEntry(boundConfigPath, connection, ttlMs);

  try {
    if (request.operation === "execute") {
      const remoteCommand = request.directory ? `cd -- ${JSON.stringify(request.directory)} && ${request.command}` : request.command;
      const stdout = await runSerialized(entry, (client) => {
        return executeRemoteCommandWithClient(client, connection, remoteCommand, request.timeout);
      });
      return { stdout };
    }
    if (request.operation === "upload") {
      const localPath = validateLocalPath(configs, request.localPath, request.cwd);
      await runSerialized(entry, (client) => uploadFileWithClient(client, localPath, request.remotePath));
      return {};
    }
    if (request.operation === "download") {
      const localPath = validateLocalPath(configs, request.localPath, request.cwd);
      fs.mkdirSync(path.dirname(localPath), { recursive: true });
      await runSerialized(entry, (client) => downloadFileWithClient(client, request.remotePath, localPath));
      return {};
    }
    throw new Error(`不支持的 daemon 操作: ${request.operation}`);
  } finally {
    entry.lastUsedAt = Date.now();
    lastActivityAt = entry.lastUsedAt;
  }
}

function handleSocket(socket) {
  socket.setEncoding("utf8");
  let buffer = "";
  socket.on("data", (chunk) => {
    buffer += chunk;
    const lineEnd = buffer.indexOf("\n");
    if (lineEnd === -1) {
      return;
    }
    const line = buffer.slice(0, lineEnd);
    activeRequests += 1;
    Promise.resolve()
      .then(() => JSON.parse(line))
      .then((request) => executeRequest(request))
      .then((result) => writeResponse(socket, { ok: true, ...result }))
      .catch((error) => writeResponse(socket, { ok: false, message: error.message }))
      .finally(() => {
        activeRequests -= 1;
        lastActivityAt = Date.now();
        scheduleExitCheck();
      });
  });
}

function shutdown() {
  clearTimeout(exitTimer);
  for (const key of Array.from(connections.keys())) {
    removeEntry(key);
  }
  if (server) {
    server.close(() => {
      try {
        unlinkSocketPath(socketPath);
      } catch (error) {
        if (error.code !== "ENOENT") {
          process.stderr.write(`${error.message}\n`);
        }
      }
      process.exit(0);
    });
    return;
  }
  process.exit(0);
}

try {
  const parsedArgs = parseArgs(process.argv.slice(2));
  socketPath = parsedArgs.socketPath;
  boundConfigPath = parsedArgs.configPath;
  daemonToken = fs.readFileSync(parsedArgs.tokenFilePath, "utf8").trim();
  unlinkSocketPath(socketPath);
  server = net.createServer(handleSocket);
  server.listen(socketPath, () => {
    chmodSocketPath(socketPath);
    scheduleExitCheck();
  });
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
