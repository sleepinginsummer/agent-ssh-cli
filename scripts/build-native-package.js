#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const platform = process.env.npm_config_platform || process.platform;
const arch = process.env.npm_config_arch || process.arch;
const executableName = platform === "win32" ? "agentsshcli-native.exe" : "agentsshcli-native";
const source = path.join(projectRoot, "native-bin", `${platform}-${arch}`, executableName);
const packageDir = path.join(projectRoot, "npm", `${platform}-${arch}`);
const targetDir = path.join(packageDir, "bin");
const target = path.join(targetDir, executableName);
const packageName = `@agent-ssh-cli/${platform}-${arch}`;
const version = JSON.parse(fs.readFileSync(path.join(projectRoot, "package.json"), "utf8")).version;

const osMap = { darwin: "darwin", linux: "linux", win32: "win32" };
const cpuMap = { arm64: "arm64", x64: "x64" };
if (!osMap[platform] || !cpuMap[arch]) {
  console.error(`暂不支持的平台: ${platform}-${arch}`);
  process.exit(1);
}
if (!fs.existsSync(source)) {
  console.error(`未找到预编译产物: ${source}，请先运行 npm run build:native-bin`);
  process.exit(1);
}
fs.mkdirSync(targetDir, { recursive: true });
fs.copyFileSync(source, target);
if (platform !== "win32") {
  fs.chmodSync(target, 0o755);
}
const pkg = {
  name: packageName,
  version,
  description: `agent-ssh-cli native binary for ${platform}-${arch}`,
  license: "MIT",
  repository: {
    type: "git",
    url: "https://github.com/sleepinginsummer/agent-ssh-cli"
  },
  os: [osMap[platform]],
  cpu: [cpuMap[arch]],
  files: ["bin/"],
  publishConfig: {
    access: "public"
  }
};
fs.writeFileSync(path.join(packageDir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`, "utf8");
console.log(`已生成平台子包 ${path.relative(projectRoot, packageDir)}`);
