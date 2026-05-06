import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const DEFAULT_CONFIG_DIR = ".agent-ssh-cli";
const DEFAULT_CONFIG_FILE = "config.json";
const configCache = new Map();

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function ensureRegexArray(patterns, fieldName, index) {
  if (patterns === undefined) {
    return [];
  }
  if (!Array.isArray(patterns)) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项的 ${fieldName} 必须是字符串数组`);
  }
  return patterns.map((pattern) => {
    if (!isNonEmptyString(pattern)) {
      throw new Error(`ssh-config.json 第 ${index + 1} 项的 ${fieldName} 必须只包含非空字符串`);
    }
    try {
      return {
        pattern,
        regex: new RegExp(pattern)
      };
    } catch (error) {
      throw new Error(`ssh-config.json 第 ${index + 1} 项的 ${fieldName} 含有非法正则: ${pattern}，${error.message}`);
    }
  });
}

function ensureStringArray(values, fieldName, index) {
  if (values === undefined) {
    return [];
  }
  if (!Array.isArray(values)) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项的 ${fieldName} 必须是字符串数组`);
  }
  return values.map((value) => {
    if (!isNonEmptyString(value)) {
      throw new Error(`ssh-config.json 第 ${index + 1} 项的 ${fieldName} 必须只包含非空字符串`);
    }
    return value;
  });
}

function normalizeConfigEntry(entry, index) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项必须是对象`);
  }
  if (!isNonEmptyString(entry.name)) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项缺少合法的 name`);
  }
  if (!isNonEmptyString(entry.host)) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项缺少合法的 host`);
  }
  if (!isNonEmptyString(entry.username)) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项缺少合法的 username`);
  }
  const port = Number(entry.port || 22);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项的 port 非法`);
  }
  if (entry.pty !== undefined && typeof entry.pty !== "boolean") {
    throw new Error(`ssh-config.json 第 ${index + 1} 项的 pty 必须是布尔值`);
  }
  const hasPassword = isNonEmptyString(entry.password);
  const hasPrivateKey = isNonEmptyString(entry.privateKey);
  const hasAgent = isNonEmptyString(entry.agent);
  const authMethodCount = [hasPassword, hasPrivateKey, hasAgent].filter(Boolean).length;
  if (authMethodCount === 0) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项必须配置 password、privateKey 或 agent 其中之一`);
  }
  if (authMethodCount > 1) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项同时配置了多个认证方式，只允许保留一种`);
  }
  if (entry.passphrase !== undefined && !isNonEmptyString(entry.passphrase)) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项的 passphrase 必须是非空字符串`);
  }
  if (entry.socksProxy !== undefined && !isNonEmptyString(entry.socksProxy)) {
    throw new Error(`ssh-config.json 第 ${index + 1} 项的 socksProxy 必须是非空字符串`);
  }
  return {
    name: entry.name,
    host: entry.host,
    port,
    username: entry.username,
    password: hasPassword ? entry.password : undefined,
    privateKey: hasPrivateKey ? entry.privateKey : undefined,
    passphrase: entry.passphrase,
    agent: hasAgent ? entry.agent : undefined,
    socksProxy: entry.socksProxy,
    pty: entry.pty,
    allowedLocalPaths: ensureStringArray(entry.allowedLocalPaths, "allowedLocalPaths", index),
    commandWhitelist: ensureRegexArray(entry.commandWhitelist, "commandWhitelist", index),
    commandBlacklist: ensureRegexArray(entry.commandBlacklist, "commandBlacklist", index)
  };
}

export function getProjectRoot() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

export function getDefaultConfigPath() {
  if (isNonEmptyString(process.env.AGENT_SSH_CONFIG)) {
    return path.resolve(process.env.AGENT_SSH_CONFIG);
  }
  return path.join(os.homedir(), DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILE);
}

export function loadConfig(configPath = getDefaultConfigPath()) {
  const resolvedConfigPath = path.resolve(configPath);
  const stat = fs.statSync(resolvedConfigPath);
  const cached = configCache.get(resolvedConfigPath);
  if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
    return cached.configs;
  }
  const raw = fs.readFileSync(resolvedConfigPath, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`ssh-config.json 解析失败: ${error.message}`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error("ssh-config.json 必须是数组格式");
  }
  const configs = parsed.map((item, index) => normalizeConfigEntry(item, index));
  if (configs.length === 0) {
    throw new Error("ssh-config.json 不能为空");
  }
  const seenNames = new Set();
  for (const config of configs) {
    if (seenNames.has(config.name)) {
      throw new Error(`ssh-config.json 存在重复的连接名: ${config.name}`);
    }
    seenNames.add(config.name);
  }
  configCache.set(resolvedConfigPath, {
    mtimeMs: stat.mtimeMs,
    size: stat.size,
    configs
  });
  return configs;
}

export function findConnection(configs, connectionName) {
  const name = connectionName || configs[0]?.name;
  const config = configs.find((item) => item.name === name);
  if (!config) {
    throw new Error(`未找到连接配置: ${name}`);
  }
  return config;
}

export function validateLocalPath(configs, localPath, baseCwd = process.cwd()) {
  const resolvedCwd = path.resolve(baseCwd);
  const resolvedPath = path.resolve(resolvedCwd, localPath);
  const allowedRoots = new Set([resolvedCwd, getProjectRoot()]);
  for (const config of configs) {
    for (const allowedPath of config.allowedLocalPaths || []) {
      allowedRoots.add(path.resolve(allowedPath));
    }
  }
  const isAllowed = Array.from(allowedRoots).some((allowedRoot) => {
    return resolvedPath === allowedRoot || resolvedPath.startsWith(`${allowedRoot}${path.sep}`);
  });
  if (!isAllowed) {
    throw new Error("本地路径不允许访问，必须位于当前工作目录、项目目录或显式允许的路径内");
  }
  return resolvedPath;
}
