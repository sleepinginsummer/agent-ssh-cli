import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getSocketPath } from "./daemon-paths.js";

const DAEMON_START_TIMEOUT_MS = 3000;
const DAEMON_REQUEST_TIMEOUT_MS = 86400000;

function getDaemonEntryPath() {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), "ssh-daemon.js");
}

function isMissingSocketError(error) {
  return ["ENOENT", "ECONNREFUSED"].includes(error.code);
}

function unlinkSocket(socketPath) {
  try {
    fs.unlinkSync(socketPath);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
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

function spawnDaemon(socketPath) {
  const child = spawn(process.execPath, [getDaemonEntryPath(), "--socket", socketPath], {
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

async function ensureDaemon(socketPath) {
  try {
    const socket = await connectSocket(socketPath, 500);
    socket.end();
    return;
  } catch (error) {
    if (!isMissingSocketError(error)) {
      throw error;
    }
    if (error.code === "ECONNREFUSED") {
      unlinkSocket(socketPath);
    }
  }
  spawnDaemon(socketPath);
  await waitForDaemon(socketPath);
}

export async function requestDaemon(configPath, request) {
  const socketPath = getSocketPath(configPath);
  await ensureDaemon(socketPath);
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
    socket.write(`${JSON.stringify(request)}\n`);
  });
}
