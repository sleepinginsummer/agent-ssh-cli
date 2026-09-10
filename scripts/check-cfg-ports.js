#!/usr/bin/env node
// 平台分支静态检查：macOS/Linux 上无法编译 Windows 目标，以下三类问题只在 win32 CI 才暴露，
// 这里按源码结构提前拦截（历史上曾两次因此导致发布失败）：
//   1. 同一函数的 #[cfg(unix)] / #[cfg(not(unix))] 两套变体可见性不一致；
//   2. 跨模块引用到的 cfg 项缺少 pub(crate)（本地编译只看得到当前平台的分支）；
//   3. #[cfg(...)] 贴在了与平台无关的 use 上（多为删除相邻 import 时留下的孤儿属性）。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = path.join(projectRoot, "native", "src");
const files = fs.readdirSync(srcDir).filter((name) => name.endsWith(".rs"));
const contents = new Map(files.map((name) => [name, fs.readFileSync(path.join(srcDir, name), "utf8").split("\n")]));

const itemPattern = /^(pub\(crate\) |pub )?(?:async )?fn (\w+)|^(pub\(crate\) |pub )?(?:struct|enum|const) (\w+)/;
const problems = [];

// 收集带 cfg 的顶层与模块内项：{(文件, 名称): [{cfg, visibility, line}]}
const cfgItems = new Map();
for (const [file, lines] of contents) {
  let pendingCfg = null;
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("#[cfg(")) {
      pendingCfg = trimmed;
      return;
    }
    const match = itemPattern.exec(trimmed);
    if (match && pendingCfg) {
      const name = match[2] || match[4];
      const visibility = match[1] || match[3] ? "pub(crate)" : "private";
      const key = `${file}:${name}`;
      if (!cfgItems.has(key)) cfgItems.set(key, []);
      cfgItems.get(key).push({ cfg: pendingCfg, visibility, line: index + 1 });
      pendingCfg = null;
      return;
    }
    if (trimmed && !trimmed.startsWith("#[") && !trimmed.startsWith("//")) pendingCfg = null;
  });
}

// 检查 1：同一项的多套 cfg 变体可见性必须一致
for (const [key, variants] of cfgItems) {
  if (variants.length > 1 && new Set(variants.map((v) => v.visibility)).size > 1) {
    const detail = variants.map((v) => `${v.cfg} ${v.visibility} (line ${v.line})`).join(" / ");
    problems.push(`${key} 的 cfg 变体可见性不一致：${detail}`);
  }
}

// 检查 2：跨模块引用到的 cfg 项必须在所有变体上都 pub(crate)
const imported = new Map();
for (const [file, lines] of contents) {
  const text = lines.join("\n");
  for (const match of text.matchAll(/use crate::(\w+)::\{([^}]*)\};/gs)) {
    for (const raw of match[2].split(",")) {
      const name = raw.trim();
      if (!name) continue;
      const key = `${match[1]}.rs:${name}`;
      if (!imported.has(key)) imported.set(key, new Set());
      imported.get(key).add(file);
    }
  }
}
for (const [key, users] of imported) {
  const variants = cfgItems.get(key);
  if (!variants) continue;
  const leaked = variants.filter((v) => v.visibility !== "pub(crate)");
  if (leaked.length) {
    const detail = leaked.map((v) => `${v.cfg} (line ${v.line})`).join(" / ");
    problems.push(`crate::${key} 被 ${[...users].join(", ")} 跨模块引用，但以下变体不是 pub(crate)：${detail}`);
  }
}

// 检查 3：cfg 属性不应贴在平台无关的 use 上
for (const [file, lines] of contents) {
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith("#[cfg(")) return;
    const next = (lines[index + 1] || "").trim();
    // 只检查 std 导入：std 路径里没有 unix/windows 标记却被平台 cfg 包住，
    // 基本都是删除相邻 import 时留下的孤儿属性。
    if (!next.startsWith("use std::")) return;
    if (!/(unix|windows)/.test(next)) {
      problems.push(`${file}:${index + 1} 的 ${trimmed} 贴在非平台相关的 std import 上：${next}`);
    }
  });
}

if (problems.length) {
  console.error("平台分支检查未通过：");
  problems.forEach((item) => console.error(`  - ${item}`));
  process.exit(1);
}
console.log(`平台分支检查通过（扫描 ${files.length} 个源文件）`);
