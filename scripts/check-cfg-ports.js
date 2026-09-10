#!/usr/bin/env node
// 平台分支静态检查：macOS/Linux 上无法编译 Windows 目标，以下三类问题只在 win32 CI 才暴露，
// 这里按源码结构提前拦截（历史上曾三次因此导致发布失败）：
//   1. 同一声明在 #[cfg(unix)] / #[cfg(windows)] 下的多套变体可见性不一致；
//   2. 跨模块引用到的私有项（含单向 #[cfg(windows)] use crate::x::y; 这种本地编译看不到的引用）；
//   3. #[cfg(...)] 贴在了与平台无关的 std import 上（多为删除相邻 import 时留下的孤儿属性）。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = path.join(projectRoot, "native", "src");
const entryFile = "main.rs";
const files = fs.readdirSync(srcDir).filter((name) => name.endsWith(".rs"));
const contents = new Map(files.map((name) => [name, fs.readFileSync(path.join(srcDir, name), "utf8").split("\n")]));

const itemPattern = /^(pub\(crate\) |pub )?(?:async )?fn (\w+)|^(pub\(crate\) |pub )?(?:struct|enum|const|static) (\w+)/;
const problems = [];

// 收集声明：{文件: 名称 → [{cfg, visibility, line}]}
const declarations = new Map();
for (const [file, lines] of contents) {
  let pendingCfg = null;
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("#[cfg(")) {
      pendingCfg = trimmed;
      return;
    }
    const match = itemPattern.exec(trimmed);
    if (match) {
      const name = match[2] || match[4];
      const visibility = match[1] || match[3] ? "pub(crate)" : "private";
      const key = `${file}:${name}`;
      if (!declarations.has(key)) declarations.set(key, []);
      declarations.get(key).push({ cfg: pendingCfg, visibility, line: index + 1 });
    }
    if (trimmed && !trimmed.startsWith("#[") && !trimmed.startsWith("//")) pendingCfg = null;
  });
}

// 检查 1：同一项的多套 cfg 变体可见性必须一致
for (const [key, variants] of declarations) {
  if (variants.length > 1 && new Set(variants.map((v) => v.visibility)).size > 1) {
    const detail = variants.map((v) => `${v.cfg} ${v.visibility} (line ${v.line})`).join(" / ");
    problems.push(`${key} 的 cfg 变体可见性不一致：${detail}`);
  }
}

// 收集跨模块 import：支持 use crate::mod::{a, b}; 、use crate::mod::name; 与带 cfg 的单向 import
const imports = [];
for (const [file, lines] of contents) {
  let pendingCfg = null;
  for (let i = 0; i < lines.length; i += 1) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith("#[cfg(")) {
      pendingCfg = trimmed;
      continue;
    }
    if (!trimmed.startsWith("use crate::")) {
      if (trimmed && !trimmed.startsWith("#[") && !trimmed.startsWith("//")) pendingCfg = null;
      continue;
    }
    let statement = trimmed;
    let cursor = i;
    while (!statement.includes(";") && cursor + 1 < lines.length) {
      cursor += 1;
      statement += ` ${lines[cursor].trim()}`;
    }
    const grouped = /^use crate::(\w+)::\{(.*)\};$/s.exec(statement);
    if (grouped) {
      for (const raw of grouped[2].split(",")) {
        const name = raw.trim();
        if (name && name !== "self") imports.push({ file, module: grouped[1], name, cfg: pendingCfg });
      }
    } else {
      const single = /^use crate::(\w+)::(\w+);$/.exec(statement);
      if (single) imports.push({ file, module: single[1], name: single[2], cfg: pendingCfg });
    }
    pendingCfg = null;
    i = cursor;
  }
}

// 检查 2：跨模块引用的声明必须是 pub(crate)；带 cfg 的 import 本地编译看不到，必须静态拦住
for (const item of imports) {
  const key = `${item.module}.rs:${item.name}`;
  const variants = declarations.get(key);
  if (!variants) continue; // 可能来自标准库同名项或模块别名，交由编译器判断
  const leaked = variants.filter((v) => v.visibility !== "pub(crate)");
  if (!leaked.length) continue;
  const scope = item.cfg ? `（${item.cfg} 分支本地编译不覆盖）` : "";
  const detail = leaked.map((v) => `${v.cfg || "无 cfg"} (line ${v.line})`).join(" / ");
  problems.push(`${item.file} 引用 crate::${item.module}::${item.name}${scope}，但该声明不是 pub(crate)：${detail}`);
}

// 检查 3：cfg 属性不应贴在平台无关的 std import 上
for (const [file, lines] of contents) {
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith("#[cfg(")) return;
    const next = (lines[index + 1] || "").trim();
    if (!next.startsWith("use std::")) return;
    if (!/(unix|windows)/.test(next)) {
      problems.push(`${file}:${index + 1} 的 ${trimmed} 贴在非平台相关的 std import 上：${next}`);
    }
  });
}

// 根模块（main.rs）自身声明对子模块天然可见，上面的 import 收集已排除 use crate::{...}
void entryFile;

if (problems.length) {
  console.error("平台分支检查未通过：");
  problems.forEach((item) => console.error(`  - ${item}`));
  process.exit(1);
}
console.log(`平台分支检查通过（扫描 ${files.length} 个源文件，${imports.length} 条跨模块 import）`);
