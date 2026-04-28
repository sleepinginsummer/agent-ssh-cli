import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

export const DEFAULT_CACHE_TTL_MS = 180000;

export function ensureSupportedPlatform() {
  if (process.platform === "win32") {
    throw new Error("当前 SSH 连接缓存池暂不支持 Windows");
  }
}

export function getDaemonDir() {
  ensureSupportedPlatform();
  const uid = typeof process.getuid === "function" ? process.getuid() : "nouid";
  const daemonDir = path.join(os.tmpdir(), `agent-ssh-cli-${uid}`);
  fs.mkdirSync(daemonDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(daemonDir, 0o700);
  return daemonDir;
}

export function getSocketPath(configPath) {
  ensureSupportedPlatform();
  const digest = crypto.createHash("sha256").update(path.resolve(configPath)).digest("hex").slice(0, 24);
  return path.join(getDaemonDir(), `${digest}.sock`);
}

export function normalizeCacheTtl(value) {
  const ttl = value === undefined ? DEFAULT_CACHE_TTL_MS : Number(value);
  if (!Number.isInteger(ttl) || ttl <= 0) {
    throw new Error("cache-ttl 必须是正整数毫秒值");
  }
  return ttl;
}
