import fs from "node:fs";
import { Client } from "ssh2";

function compilePatterns(patterns, label) {
  return (patterns || []).map((pattern) => {
    try {
      return new RegExp(pattern);
    } catch (error) {
      throw new Error(`${label} 正则非法: ${pattern}，${error.message}`);
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

function createConnectConfig(connection) {
  const connectConfig = {
    host: connection.host,
    port: connection.port,
    username: connection.username
  };
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
  const connectConfig = createConnectConfig(connection);
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
    const timer = setTimeout(() => {
      settled = true;
      reject(new Error(`命令执行超时，超过 ${timeout}ms`));
    }, timeout);

    client.exec(remoteCommand, { pty: connection.pty ?? true }, (err, stream) => {
      if (err) {
        clearTimeout(timer);
        reject(err);
        return;
      }

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
        clearTimeout(timer);
        if (settled) {
          return;
        }
        settled = true;
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
          reject(new Error(parts.join("\n") || "命令执行失败"));
          return;
        }
        resolve(stdout.trimEnd());
      });
      stream.on("error", (streamError) => {
        clearTimeout(timer);
        if (settled) {
          return;
        }
        settled = true;
        reject(streamError);
      });
    });
  });
}

export async function uploadFile(connection, localPath, remotePath) {
  return withConnection(connection, (client) => uploadFileWithClient(client, localPath, remotePath));
}

export async function uploadFileWithClient(client, localPath, remotePath) {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) {
        reject(err);
        return;
      }
      const readStream = fs.createReadStream(localPath);
      const writeStream = sftp.createWriteStream(remotePath);
      let closed = false;
      const cleanup = () => {
        if (!closed) {
          closed = true;
          sftp.end();
        }
      };

      readStream.on("error", (readError) => {
        cleanup();
        reject(readError);
      });
      writeStream.on("error", (writeError) => {
        cleanup();
        reject(writeError);
      });
      writeStream.on("close", () => {
        cleanup();
        resolve();
      });
      readStream.pipe(writeStream);
    });
  });
}

export async function downloadFile(connection, remotePath, localPath) {
  return withConnection(connection, (client) => downloadFileWithClient(client, remotePath, localPath));
}

export async function downloadFileWithClient(client, remotePath, localPath) {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) {
        reject(err);
        return;
      }
      const readStream = sftp.createReadStream(remotePath);
      const writeStream = fs.createWriteStream(localPath);
      let closed = false;
      const cleanup = () => {
        if (!closed) {
          closed = true;
          sftp.end();
        }
      };

      readStream.on("error", (readError) => {
        cleanup();
        reject(readError);
      });
      writeStream.on("error", (writeError) => {
        cleanup();
        reject(writeError);
      });
      writeStream.on("close", () => {
        cleanup();
        resolve();
      });
      readStream.pipe(writeStream);
    });
  });
}
