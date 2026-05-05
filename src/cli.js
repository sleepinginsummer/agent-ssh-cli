import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { loadConfig, findConnection, validateLocalPath, getDefaultConfigPath } from "./config.js";
import { requestDaemon } from "./daemon-client.js";
import { normalizeCacheTtl } from "./daemon-paths.js";
import { executeRemoteCommand, uploadFile, downloadFile } from "./ssh-client.js";

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const packageJson = JSON.parse(fs.readFileSync(path.join(currentDir, "..", "package.json"), "utf8"));

const HELP_TEXT = {
  agentsshcli: `
用法:
  agentsshcli list [--config <path>] [--json]
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] <connectionName> <command>
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] --connection <name> --command <command> [--directory <dir>] [--timeout <ms>]
  agentsshcli upload [--config <path>] [--no-cache] [--cache-ttl <ms>] <connectionName> <localPath> <remotePath>
  agentsshcli upload [--config <path>] [--no-cache] [--cache-ttl <ms>] --connection <name> --local <path> --remote <path>
  agentsshcli download [--config <path>] [--no-cache] [--cache-ttl <ms>] <connectionName> <remotePath> <localPath>
  agentsshcli download [--config <path>] [--no-cache] [--cache-ttl <ms>] --connection <name> --remote <path> --local <path>
  agentsshcli init-config
  agentsshcli help [list|exec|upload|download]
  agentsshcli --help
  agentsshcli --version

说明:
  agent-ssh-cli 统一入口。
`,
  sshls: `
用法:
  agentsshcli list [--config <path>] [--json]
  agentsshcli help list
  agentsshcli --version

说明:
  列出当前配置文件中的 SSH 连接。
`,
  sshx: `
用法:
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] <connectionName> <command>
  agentsshcli exec [--config <path>] [--no-cache] [--cache-ttl <ms>] --connection <name> --command <command> [--directory <dir>] [--timeout <ms>]
  agentsshcli help exec
  agentsshcli --version

说明:
  在远端执行命令。
`,
  sshupload: `
用法:
  agentsshcli upload [--config <path>] [--no-cache] [--cache-ttl <ms>] <connectionName> <localPath> <remotePath>
  agentsshcli upload [--config <path>] [--no-cache] [--cache-ttl <ms>] --connection <name> --local <path> --remote <path>
  agentsshcli help upload
  agentsshcli --version

说明:
  上传本地文件到远端。
`,
  sshdownload: `
用法:
  agentsshcli download [--config <path>] [--no-cache] [--cache-ttl <ms>] <connectionName> <remotePath> <localPath>
  agentsshcli download [--config <path>] [--no-cache] [--cache-ttl <ms>] --connection <name> --remote <path> --local <path>
  agentsshcli help download
  agentsshcli --version

说明:
  下载远端文件到本地。
`
};

function printHelp(commandName) {
  process.stdout.write(`${HELP_TEXT[commandName].trim()}\n`);
}

function printVersion() {
  process.stdout.write(`${packageJson.version}\n`);
}

function getHelpName(commandName) {
  const names = {
    list: "sshls",
    exec: "sshx",
    upload: "sshupload",
    download: "sshdownload"
  };
  return names[commandName] || commandName;
}

function initConfig() {
  const target = getDefaultConfigPath();
  const source = path.join(currentDir, "..", "example.config.json");
  if (fs.existsSync(target)) {
    throw new Error(`${target} 已存在，未覆盖`);
  }
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  fs.copyFileSync(source, target);
  process.stdout.write(`已创建 ${target}\n`);
}

function parseGlobalArgs(argv) {
  const args = [...argv];
  let configPath = getDefaultConfigPath();
  let help = false;
  let version = false;
  let json = false;
  let noCache = false;
  let cacheTtlMs;
  const remaining = [];

  while (args.length > 0) {
    const current = args.shift();
    if (current === "--help" || current === "-h") {
      help = true;
      continue;
    }
    if (current === "--version" || current === "-v") {
      version = true;
      continue;
    }
    if (current === "--json") {
      json = true;
      continue;
    }
    if (current === "--no-cache") {
      noCache = true;
      continue;
    }
    if (current === "--cache-ttl") {
      const value = args.shift();
      if (!value) {
        throw new Error("--cache-ttl 缺少毫秒值");
      }
      cacheTtlMs = normalizeCacheTtl(value);
      continue;
    }
    if (current === "--config") {
      const value = args.shift();
      if (!value) {
        throw new Error("--config 缺少路径");
      }
      configPath = path.resolve(value);
      continue;
    }
    remaining.push(current, ...args);
    break;
  }

  return {
    configPath,
    help,
    version,
    json,
    noCache,
    cacheTtlMs,
    args: remaining
  };
}

function findOptionIndexes(args, names) {
  const indexes = [];
  for (let index = 0; index < args.length; index += 1) {
    if (names.includes(args[index])) {
      indexes.push(index);
    }
  }
  return indexes;
}

function takeOption(args, names) {
  const indexes = findOptionIndexes(args, names);
  if (indexes.length > 1) {
    throw new Error(`参数重复声明: ${names[0]}`);
  }
  if (indexes.length === 0) {
    return {
      present: false,
      value: undefined
    };
  }
  const index = indexes[0];
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${args[index]} 缺少参数值`);
  }
  args.splice(index, 2);
  return {
    present: true,
    value
  };
}

function ensureNoUnknownOptions(args) {
  const unknown = args.find((item) => item.startsWith("--"));
  if (unknown) {
    throw new Error(`不支持的参数: ${unknown}`);
  }
}

function ensureNoExtraPositionals(args) {
  if (args.length > 0) {
    throw new Error(`存在多余的位置参数: ${args.join(" ")}`);
  }
}

function takePositional(args, fieldName) {
  const value = args.shift();
  if (value && value.startsWith("--")) {
    throw new Error(`${fieldName} 位置参数非法: ${value}`);
  }
  return value;
}

function ensureNoMixedInput(namedValue, positionalValue, fieldName) {
  if (namedValue !== undefined && positionalValue !== undefined) {
    throw new Error(`${fieldName} 同时使用了命名参数和位置参数，保留一种即可`);
  }
}

function resolveValue(args, optionNames, fieldName) {
  const namedOption = takeOption(args, optionNames);
  if (namedOption.present) {
    return namedOption.value;
  }
  return takePositional(args, fieldName);
}

function parseListArgs(argv) {
  const parsed = parseGlobalArgs(argv);
  if (parsed.help || parsed.version) {
    return parsed;
  }
  if (parsed.args.length > 0) {
    throw new Error(`agentsshcli list 不接受位置参数: ${parsed.args.join(" ")}`);
  }
  return parsed;
}

function parseExecuteArgs(argv) {
  const parsed = parseGlobalArgs(argv);
  if (parsed.help || parsed.version) {
    return parsed;
  }
  const args = [...parsed.args];
  const connectionNameOption = takeOption(args, ["--connection", "-c"]);
  const commandOption = takeOption(args, ["--command"]);
  const directoryOption = takeOption(args, ["--directory", "-d"]);
  const timeoutOption = takeOption(args, ["--timeout", "-t"]);
  const connectionNamePositional = takePositional(args, "connectionName");
  const commandPositional = takePositional(args, "command");

  ensureNoMixedInput(connectionNameOption.present ? connectionNameOption.value : undefined, connectionNamePositional, "connectionName");
  ensureNoMixedInput(commandOption.present ? commandOption.value : undefined, commandPositional, "command");

  const connectionName = connectionNameOption.present ? connectionNameOption.value : connectionNamePositional;
  const command = commandOption.present ? commandOption.value : commandPositional;
  const directory = directoryOption.present ? directoryOption.value : undefined;
  const timeoutValue = timeoutOption.present ? timeoutOption.value : undefined;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index]?.startsWith("--")) {
      throw new Error(`不支持的参数: ${args[index]}`);
    }
  }
  ensureNoUnknownOptions(args);
  ensureNoExtraPositionals(args);
  if (!connectionName || !command) {
    throw new Error("缺少必填参数 connectionName 或 command，使用 --help 查看说明");
  }
  const timeout = timeoutValue === undefined ? 30000 : Number(timeoutValue);
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new Error("timeout 必须是正整数毫秒值");
  }
  return {
    ...parsed,
    connectionName,
    command,
    directory,
    timeout
  };
}

function parseTransferArgs(argv, mode) {
  const parsed = parseGlobalArgs(argv);
  if (parsed.help || parsed.version) {
    return parsed;
  }
  const args = [...parsed.args];
  const connectionName = resolveValue(args, ["--connection", "-c"], "connectionName");
  const localOptionNames = ["--local", "-l"];
  const remoteOptionNames = ["--remote", "-r"];
  let localPath;
  let remotePath;

  if (mode === "upload") {
    localPath = resolveValue(args, localOptionNames, "localPath");
    remotePath = resolveValue(args, remoteOptionNames, "remotePath");
  } else {
    remotePath = resolveValue(args, remoteOptionNames, "remotePath");
    localPath = resolveValue(args, localOptionNames, "localPath");
  }

  ensureNoUnknownOptions(args);
  ensureNoExtraPositionals(args);

  if (!connectionName || !localPath || !remotePath) {
    throw new Error("缺少必填参数，使用 --help 查看说明");
  }

  return {
    ...parsed,
    connectionName,
    localPath,
    remotePath
  };
}

export async function runListServers(argv) {
  const parsed = parseListArgs(argv);
  if (parsed.help) {
    printHelp("sshls");
    return;
  }
  if (parsed.version) {
    printVersion();
    return;
  }
  const configs = loadConfig(parsed.configPath);
  const output = configs.map((item) => ({
    name: item.name,
    host: item.host,
    port: item.port,
    username: item.username
  }));
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}

export async function runExecute(argv) {
  const parsed = parseExecuteArgs(argv);
  if (parsed.help) {
    printHelp("sshx");
    return;
  }
  if (parsed.version) {
    printVersion();
    return;
  }
  const configs = loadConfig(parsed.configPath);
  const connection = findConnection(configs, parsed.connectionName);
  const result = parsed.noCache
    ? await executeRemoteCommand(connection, parsed.command, parsed.directory, parsed.timeout)
    : (await requestDaemon(parsed.configPath, {
        operation: "execute",
        configPath: parsed.configPath,
        cwd: process.cwd(),
        connectionName: parsed.connectionName,
        command: parsed.command,
        directory: parsed.directory,
        timeout: parsed.timeout,
        cacheTtlMs: parsed.cacheTtlMs
      })).stdout;
  if (result) {
    process.stdout.write(`${result}\n`);
  }
}

export async function runUpload(argv) {
  const parsed = parseTransferArgs(argv, "upload");
  if (parsed.help) {
    printHelp("sshupload");
    return;
  }
  if (parsed.version) {
    printVersion();
    return;
  }
  const configs = loadConfig(parsed.configPath);
  const connection = findConnection(configs, parsed.connectionName);
  if (parsed.noCache) {
    const validatedLocalPath = validateLocalPath(configs, parsed.localPath);
    await uploadFile(connection, validatedLocalPath, parsed.remotePath);
  } else {
    await requestDaemon(parsed.configPath, {
      operation: "upload",
      configPath: parsed.configPath,
      cwd: process.cwd(),
      connectionName: parsed.connectionName,
      localPath: parsed.localPath,
      remotePath: parsed.remotePath,
      cacheTtlMs: parsed.cacheTtlMs
    });
  }
  process.stdout.write("File uploaded successfully\n");
}

export async function runDownload(argv) {
  const parsed = parseTransferArgs(argv, "download");
  if (parsed.help) {
    printHelp("sshdownload");
    return;
  }
  if (parsed.version) {
    printVersion();
    return;
  }
  const configs = loadConfig(parsed.configPath);
  const connection = findConnection(configs, parsed.connectionName);
  if (parsed.noCache) {
    const validatedLocalPath = validateLocalPath(configs, parsed.localPath);
    fs.mkdirSync(path.dirname(validatedLocalPath), { recursive: true });
    await downloadFile(connection, parsed.remotePath, validatedLocalPath);
  } else {
    await requestDaemon(parsed.configPath, {
      operation: "download",
      configPath: parsed.configPath,
      cwd: process.cwd(),
      connectionName: parsed.connectionName,
      localPath: parsed.localPath,
      remotePath: parsed.remotePath,
      cacheTtlMs: parsed.cacheTtlMs
    });
  }
  process.stdout.write("File downloaded successfully\n");
}

export async function runAgentSshCli(argv) {
  const [command, ...args] = argv;
  if (!command || command === "--help" || command === "-h") {
    printHelp("agentsshcli");
    return;
  }
  if (command === "--version" || command === "-v" || command === "version") {
    printVersion();
    return;
  }
  if (command === "help") {
    const target = getHelpName(args[0] || "agentsshcli");
    if (!HELP_TEXT[target]) {
      throw new Error(`未知帮助命令: ${args[0]}`);
    }
    printHelp(target);
    return;
  }
  if (command === "init-config") {
    initConfig();
    return;
  }
  if (command === "list") {
    await runListServers(args);
    return;
  }
  if (command === "exec") {
    await runExecute(args);
    return;
  }
  if (command === "upload") {
    await runUpload(args);
    return;
  }
  if (command === "download") {
    await runDownload(args);
    return;
  }
  throw new Error(`未知命令: ${command}，使用 agentsshcli --help 查看说明`);
}
