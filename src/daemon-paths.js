import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

export const DEFAULT_CACHE_TTL_MS = 180000;

export function isWindowsPlatform() {
  return process.platform === "win32";
}

export function getDaemonDir() {
  const uid = typeof process.getuid === "function" ? process.getuid() : "nouid";
  const daemonDir = path.join(os.tmpdir(), `agent-ssh-cli-${uid}`);
  fs.mkdirSync(daemonDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(daemonDir, 0o700);
  return daemonDir;
}

export function getSocketPath(configPath) {
  const digest = crypto.createHash("sha256").update(path.resolve(configPath)).digest("hex").slice(0, 24);
  if (isWindowsPlatform()) {
    // Windows 下 Node IPC 使用 named pipe，不是文件系统 socket。
    const userKey = process.env.USERPROFILE || process.env.USERNAME || os.homedir() || "nouser";
    const userDigest = crypto.createHash("sha256").update(userKey).digest("hex").slice(0, 12);
    return `\\\\.\\pipe\\agent-ssh-cli-${userDigest}-${digest}`;
  }
  return path.join(getDaemonDir(), `${digest}.sock`);
}

export function getTokenPath(configPath) {
  const digest = crypto.createHash("sha256").update(path.resolve(configPath)).digest("hex").slice(0, 24);
  return path.join(getDaemonDir(), `${digest}.token`);
}

export function unlinkSocketPath(socketPath) {
  if (isWindowsPlatform()) {
    return;
  }
  try {
    fs.unlinkSync(socketPath);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
}

export function chmodSocketPath(socketPath) {
  if (!isWindowsPlatform()) {
    fs.chmodSync(socketPath, 0o600);
  }
}

export function normalizeCacheTtl(value) {
  const ttl = value === undefined ? DEFAULT_CACHE_TTL_MS : Number(value);
  if (!Number.isInteger(ttl) || ttl <= 0) {
    throw new Error("cache-ttl 必须是正整数毫秒值");
  }
  return ttl;
}
