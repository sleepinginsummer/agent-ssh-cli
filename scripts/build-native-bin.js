#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const projectRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const targetTriple = process.env.TARGET || process.env.npm_config_target;
const tripleMap = {
  "aarch64-apple-darwin": ["darwin", "arm64"],
  "x86_64-apple-darwin": ["darwin", "x64"],
  "x86_64-unknown-linux-gnu": ["linux", "x64"],
  "x86_64-pc-windows-msvc": ["win32", "x64"],
  "x86_64-pc-windows-gnu": ["win32", "x64"]
};
const [platform, arch] = targetTriple
  ? tripleMap[targetTriple] || []
  : [process.env.npm_config_platform || process.platform, process.env.npm_config_arch || process.arch];

if (!platform || !arch) {
  console.error(`暂不支持的 Rust target: ${targetTriple}`);
  process.exit(1);
}

const executableName = platform === "win32" ? "agentsshcli-native.exe" : "agentsshcli-native";
const targetDir = path.join(projectRoot, "native-bin", `${platform}-${arch}`);

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: projectRoot,
    stdio: "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

const cargoArgs = ["build", "--release", "--manifest-path", "native/Cargo.toml"];
if (targetTriple) {
  cargoArgs.push("--target", targetTriple);
}
if (process.env.SKIP_CARGO_BUILD !== "1") {
  run("cargo", cargoArgs);
}

const source = targetTriple
  ? path.join(projectRoot, "native", "target", targetTriple, "release", executableName)
  : path.join(projectRoot, "native", "target", "release", executableName);
if (!fs.existsSync(source)) {
  console.error(`未找到构建产物: ${source}`);
  process.exit(1);
}
fs.mkdirSync(targetDir, { recursive: true });
const target = path.join(targetDir, executableName);
fs.copyFileSync(source, target);
if (platform !== "win32") {
  fs.chmodSync(target, 0o755);
}
console.log(`已生成 ${path.relative(projectRoot, target)}`);
