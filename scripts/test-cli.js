import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const projectRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const binPath = path.join(projectRoot, "bin", "agentsshcli.js");
const tmpDir = path.join(projectRoot, "tmp");
const localUploadFile = path.join(tmpDir, "upload.txt");
const localDownloadFile = path.join(tmpDir, "download.txt");
const remoteDir = "/usr/loca/test";
const remoteFile = `${remoteDir}/upload.txt`;
const connectionName = "syy阿里云";

fs.mkdirSync(tmpDir, { recursive: true });
fs.writeFileSync(localUploadFile, "agent-ssh-cli test file\n", "utf8");

function run(args) {
  return execFileSync(binPath, args, {
    cwd: projectRoot,
    env: {
      ...process.env,
      AGENT_SSH_CONFIG: path.join(projectRoot, "ssh-config.json")
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  }).trim();
}

console.log(run(["list"]));
console.log(run(["exec", connectionName, "pwd"]));
console.log(run(["exec", connectionName, `mkdir -p ${remoteDir}`]));
console.log(run(["upload", connectionName, localUploadFile, remoteFile]));
console.log(run(["download", connectionName, remoteFile, localDownloadFile]));
console.log(fs.readFileSync(localDownloadFile, "utf8").trim());
