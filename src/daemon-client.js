import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getSocketPath, getTokenPath, unlinkSocketPath } from "./daemon-paths.js";

const DAEMON_START_TIMEOUT_MS = 3000;
const DAEMON_REQUEST_TIMEOUT_MS = 86400000;

function getDaemonEntryPath() {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), "ssh-daemon.js");
}

function isMissingSocketError(error) {
  return ["ENOENT", "ECONNREFUSED"].includes(error.code);
}

function connectSocket(socketPath, timeoutMs = DAEMON_REQUEST_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener("error", onError);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const timer = setTimeout(() => {
      socket.removeListener("error", onError);
      socket.destroy();
      reject(new Error("连接 SSH 缓存进程超时"));
    }, timeoutMs);
    socket.once("connect", () => {
      cleanup();
      resolve(socket);
    });
    socket.once("error", onError);
  });
}

function readToken(tokenPath) {
  return fs.readFileSync(tokenPath, "utf8").trim();
}

function createToken(tokenPath) {
  const token = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(tokenPath, token, { mode: 0o600 });
  fs.chmodSync(tokenPath, 0o600);
  return token;
}

function spawnDaemon(socketPath, configPath, tokenPath) {
  const child = spawn(process.execPath, [getDaemonEntryPath(), "--socket", socketPath, "--config", path.resolve(configPath), "--token-file", tokenPath], {
    detached: true,
    stdio: "ignore"
  });
  child.unref();
}

async function waitForDaemon(socketPath) {
  const startAt = Date.now();
  let lastError;
  while (Date.now() - startAt < DAEMON_START_TIMEOUT_MS) {
    try {
      const socket = await connectSocket(socketPath, 500);
      socket.end();
      return;
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error(`启动 SSH 缓存进程失败: ${lastError?.message || "未知错误"}`);
}

async function ensureDaemon(socketPath, configPath, tokenPath) {
  try {
    const socket = await connectSocket(socketPath, 500);
    socket.end();
    try {
      return readToken(tokenPath);
    } catch (error) {
      unlinkSocketPath(socketPath);
    }
  } catch (error) {
    if (!isMissingSocketError(error)) {
      throw error;
    }
    if (error.code === "ECONNREFUSED") {
      unlinkSocketPath(socketPath);
    }
  }
  const token = createToken(tokenPath);
  spawnDaemon(socketPath, configPath, tokenPath);
  await waitForDaemon(socketPath);
  return token;
}

export async function requestDaemon(configPath, request) {
  const socketPath = getSocketPath(configPath);
  const tokenPath = getTokenPath(configPath);
  const token = await ensureDaemon(socketPath, configPath, tokenPath);
  const socket = await connectSocket(socketPath);
  socket.setEncoding("utf8");

  return new Promise((resolve, reject) => {
    let buffer = "";
    let settled = false;
    const cleanup = () => {
      socket.removeAllListeners();
      socket.end();
    };
    const settle = (callback, value) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback(value);
    };

    socket.on("data", (chunk) => {
      buffer += chunk;
      const lineEnd = buffer.indexOf("\n");
      if (lineEnd === -1) {
        return;
      }
      const line = buffer.slice(0, lineEnd);
      let response;
      try {
        response = JSON.parse(line);
      } catch (error) {
        settle(reject, new Error(`SSH 缓存进程响应非法: ${error.message}`));
        return;
      }
      if (!response.ok) {
        settle(reject, new Error(response.message || "SSH 缓存进程执行失败"));
        return;
      }
      settle(resolve, response);
    });
    socket.on("error", (error) => settle(reject, error));
    socket.on("close", () => {
      if (!settled) {
        settle(reject, new Error("SSH 缓存进程提前关闭连接"));
      }
    });
    socket.write(`${JSON.stringify({ ...request, token })}\n`);
  });
}
