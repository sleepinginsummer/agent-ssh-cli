import fs from "node:fs";
import net from "node:net";
import { pipeline } from "node:stream/promises";
import { Client } from "ssh2";

const SOCKS5_VERSION = 0x05;
const SOCKS5_CONNECT_COMMAND = 0x01;
const SOCKS5_RESERVED = 0x00;
const SOCKS5_AUTH_NONE = 0x00;
const SOCKS5_AUTH_PASSWORD = 0x02;
const SOCKS5_AUTH_UNACCEPTABLE = 0xff;
const SOCKS5_ADDRESS_IPV4 = 0x01;
const SOCKS5_ADDRESS_DOMAIN = 0x03;
const SOCKS5_ADDRESS_IPV6 = 0x04;
const SOCKS5_REPLY_SUCCESS = 0x00;

function getCompiledPattern(pattern, label) {
  if (pattern instanceof RegExp) {
    return pattern;
  }
  if (pattern?.regex instanceof RegExp) {
    return pattern.regex;
  }
  try {
    return new RegExp(pattern?.pattern || pattern);
  } catch (error) {
    throw new Error(`${label} 正则非法: ${pattern?.pattern || pattern}，${error.message}`);
  }
}

function compilePatterns(patterns, label) {
  return (patterns || []).map((pattern) => {
    try {
      return getCompiledPattern(pattern, label);
    } catch (error) {
      throw new Error(error.message);
    }
  });
}

export function validateCommand(connection, command) {
  const whitelist = compilePatterns(connection.commandWhitelist, "白名单");
  const blacklist = compilePatterns(connection.commandBlacklist, "黑名单");

  if (whitelist.length > 0 && !whitelist.some((item) => item.test(command))) {
    throw new Error("命令未命中白名单，拒绝执行");
  }
  if (blacklist.length > 0 && blacklist.some((item) => item.test(command))) {
    throw new Error("命令命中黑名单，拒绝执行");
  }
}

function parseSocksProxy(proxy) {
  const value = proxy.includes("://") ? proxy : `socks5://${proxy}`;
  let parsed;
  try {
    parsed = new URL(value);
  } catch (error) {
    throw new Error(`socksProxy 格式非法: ${proxy}，${error.message}`);
  }
  if (parsed.protocol !== "socks5:") {
    throw new Error("socksProxy 仅支持 socks5:// 协议");
  }
  if (!parsed.hostname || !parsed.port) {
    throw new Error("socksProxy 必须包含代理主机和端口");
  }
  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error("socksProxy 端口非法");
  }
  const username = decodeURIComponent(parsed.username);
  const password = decodeURIComponent(parsed.password);
  if ((username && !password) || (!username && password)) {
    throw new Error("socksProxy 用户名和密码必须同时提供");
  }
  return {
    host: parsed.hostname,
    port,
    username: username || undefined,
    password: password || undefined
  };
}

function readExactly(socket, length) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const cleanup = () => {
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => {
      cleanup();
      reject(new Error("SOCKS5 代理连接提前关闭"));
    };
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < length) {
        return;
      }
      const result = buffer.subarray(0, length);
      const rest = buffer.subarray(length);
      cleanup();
      if (rest.length > 0) {
        socket.unshift(rest);
      }
      resolve(result);
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}

function writeAll(socket, data) {
  return new Promise((resolve, reject) => {
    socket.write(data, (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function connectTcp(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    const cleanup = () => {
      socket.removeListener("error", onError);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    socket.once("connect", () => {
      cleanup();
      resolve(socket);
    });
    socket.once("error", onError);
  });
}

function encodeTargetAddress(host) {
  const ipVersion = net.isIP(host);
  if (ipVersion === 4) {
    return Buffer.concat([Buffer.from([SOCKS5_ADDRESS_IPV4]), Buffer.from(host.split(".").map(Number))]);
  }
  const hostBuffer = Buffer.from(host, "utf8");
  if (hostBuffer.length > 255) {
    throw new Error("SOCKS5 目标主机名过长");
  }
  return Buffer.concat([Buffer.from([SOCKS5_ADDRESS_DOMAIN, hostBuffer.length]), hostBuffer]);
}

async function authenticateSocksProxy(socket, proxyConfig) {
  const methods = proxyConfig.username ? [SOCKS5_AUTH_PASSWORD] : [SOCKS5_AUTH_NONE];
  await writeAll(socket, Buffer.from([SOCKS5_VERSION, methods.length, ...methods]));
  const response = await readExactly(socket, 2);
  if (response[0] !== SOCKS5_VERSION) {
    throw new Error("SOCKS5 代理响应版本非法");
  }
  if (response[1] === SOCKS5_AUTH_UNACCEPTABLE) {
    throw new Error("SOCKS5 代理不接受当前认证方式");
  }
  if (response[1] === SOCKS5_AUTH_NONE) {
    return;
  }
  if (response[1] !== SOCKS5_AUTH_PASSWORD || !proxyConfig.username) {
    throw new Error("SOCKS5 代理返回了不支持的认证方式");
  }
  const usernameBuffer = Buffer.from(proxyConfig.username, "utf8");
  const passwordBuffer = Buffer.from(proxyConfig.password, "utf8");
  if (usernameBuffer.length > 255 || passwordBuffer.length > 255) {
    throw new Error("SOCKS5 用户名或密码过长");
  }
  await writeAll(socket, Buffer.concat([
    Buffer.from([0x01, usernameBuffer.length]),
    usernameBuffer,
    Buffer.from([passwordBuffer.length]),
    passwordBuffer
  ]));
  const authResponse = await readExactly(socket, 2);
  if (authResponse[1] !== 0x00) {
    throw new Error("SOCKS5 代理认证失败");
  }
}

async function readSocksConnectResponse(socket) {
  const header = await readExactly(socket, 4);
  if (header[0] !== SOCKS5_VERSION) {
    throw new Error("SOCKS5 代理响应版本非法");
  }
  if (header[1] !== SOCKS5_REPLY_SUCCESS) {
    throw new Error(`SOCKS5 代理连接目标失败，响应码 ${header[1]}`);
  }
  if (header[2] !== SOCKS5_RESERVED) {
    throw new Error("SOCKS5 代理响应保留字段非法");
  }
  if (header[3] === SOCKS5_ADDRESS_IPV4) {
    await readExactly(socket, 4);
  } else if (header[3] === SOCKS5_ADDRESS_IPV6) {
    await readExactly(socket, 16);
  } else if (header[3] === SOCKS5_ADDRESS_DOMAIN) {
    const length = (await readExactly(socket, 1))[0];
    await readExactly(socket, length);
  } else {
    throw new Error("SOCKS5 代理响应地址类型非法");
  }
  await readExactly(socket, 2);
}

async function connectSocksProxy(connection) {
  const proxyConfig = parseSocksProxy(connection.socksProxy);
  const socket = await connectTcp(proxyConfig.host, proxyConfig.port);
  try {
    await authenticateSocksProxy(socket, proxyConfig);
    const targetAddress = encodeTargetAddress(connection.host);
    const targetPort = Buffer.alloc(2);
    targetPort.writeUInt16BE(connection.port);
    await writeAll(socket, Buffer.concat([
      Buffer.from([SOCKS5_VERSION, SOCKS5_CONNECT_COMMAND, SOCKS5_RESERVED]),
      targetAddress,
      targetPort
    ]));
    await readSocksConnectResponse(socket);
    return socket;
  } catch (error) {
    socket.destroy();
    throw error;
  }
}

async function createConnectConfig(connection) {
  const connectConfig = {
    host: connection.host,
    port: connection.port,
    username: connection.username
  };
  if (connection.socksProxy) {
    connectConfig.sock = await connectSocksProxy(connection);
  }
  if (connection.agent) {
    connectConfig.agent = connection.agent;
  } else if (connection.privateKey) {
    connectConfig.privateKey = fs.readFileSync(connection.privateKey, "utf8");
    if (connection.passphrase) {
      connectConfig.passphrase = connection.passphrase;
    }
  } else if (connection.password) {
    connectConfig.password = connection.password;
  } else {
    throw new Error(`连接 ${connection.name} 缺少可用认证信息`);
  }
  return connectConfig;
}

export async function connectSshClient(connection) {
  const client = new Client();
  const connectConfig = await createConnectConfig(connection);
  await new Promise((resolve, reject) => {
    client.once("ready", resolve);
    client.once("error", reject);
    client.connect(connectConfig);
  });
  return client;
}

export async function withConnection(connection, handler) {
  const client = await connectSshClient(connection);
  try {
    return await handler(client);
  } finally {
    client.end();
  }
}

export async function executeRemoteCommand(connection, command, directory, timeout = 30000) {
  validateCommand(connection, command);
  const remoteCommand = directory ? `cd -- ${JSON.stringify(directory)} && ${command}` : command;
  return withConnection(connection, (client) => executeRemoteCommandWithClient(client, connection, remoteCommand, timeout));
}

export async function executeRemoteCommandWithClient(client, connection, remoteCommand, timeout = 30000) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let exitCode;
    let exitSignal;
    let settled = false;
    let commandStream;
    const settle = (callback, value) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const timer = setTimeout(() => {
      if (commandStream) {
        commandStream.close();
      }
      settle(reject, new Error(`命令执行超时，超过 ${timeout}ms`));
    }, timeout);

    client.exec(remoteCommand, { pty: connection.pty ?? true }, (err, stream) => {
      if (err) {
        settle(reject, err);
        return;
      }
      commandStream = stream;

      stream.on("data", (chunk) => {
        stdout += chunk.toString();
      });
      stream.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
      });
      stream.on("exit", (code, signal) => {
        exitCode = code;
        exitSignal = signal;
      });
      stream.on("close", (code, signal) => {
        if (settled) {
          return;
        }
        exitCode = exitCode ?? code;
        exitSignal = exitSignal ?? signal;
        if ((exitCode ?? 0) !== 0 || exitSignal) {
          const parts = [];
          if (stdout.trim()) {
            parts.push(stdout.trimEnd());
          }
          if (stderr.trim()) {
            parts.push(`[stderr]\n${stderr.trimEnd()}`);
          }
          if (exitCode !== undefined) {
            parts.push(`[exit code] ${exitCode}`);
          }
          if (exitSignal) {
            parts.push(`[signal] ${exitSignal}`);
          }
          settle(reject, new Error(parts.join("\n") || "命令执行失败"));
          return;
        }
        settle(resolve, stdout.trimEnd());
      });
      stream.on("error", (streamError) => {
        settle(reject, streamError);
      });
    });
  });
}

export async function uploadFile(connection, localPath, remotePath) {
  return withConnection(connection, (client) => uploadFileWithClient(client, localPath, remotePath));
}

export async function uploadFileWithClient(client, localPath, remotePath) {
  const sftp = await new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(sftp);
    });
  });
  try {
    await pipeline(fs.createReadStream(localPath), sftp.createWriteStream(remotePath));
  } finally {
    sftp.end();
  }
}

export async function downloadFile(connection, remotePath, localPath) {
  return withConnection(connection, (client) => downloadFileWithClient(client, remotePath, localPath));
}

export async function downloadFileWithClient(client, remotePath, localPath) {
  const sftp = await new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(sftp);
    });
  });
  try {
    await pipeline(sftp.createReadStream(remotePath), fs.createWriteStream(localPath));
  } finally {
    sftp.end();
  }
}
