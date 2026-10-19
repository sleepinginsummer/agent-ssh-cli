#!/usr/bin/env node
// 版本同步与校验：以 package.json 为唯一真相源，把同一个版本写进 Cargo.toml。
//
// 用法：
//   node scripts/sync-version.mjs                    # 把 package.json 的版本写入 Cargo.toml 并 git add
//   node scripts/sync-version.mjs --check            # 校验 package.json 与 Cargo.toml 一致
//   node scripts/sync-version.mjs --check --expect 0.3.7   # 再把 tag 版本一并校验
//   node scripts/sync-version.mjs --cargo native/Cargo.toml
//
// 退出码：0 一致 / 已写入；1 不一致或文件缺失，CI 直接失败。

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const CANDIDATES = ['Cargo.toml', 'native/Cargo.toml', 'rust/Cargo.toml'];

function parseArgs(argv) {
  const args = { check: false, expect: null, cargo: null };
  for (let i = 0; i < argv.length; i += 1) {
    const current = argv[i];
    if (current === '--check') args.check = true;
    else if (current === '--expect') args.expect = argv[++i] ?? null;
    else if (current === '--cargo') args.cargo = argv[++i] ?? null;
    else if (current === '--help' || current === '-h') {
      console.log('用法: sync-version.mjs [--check] [--expect <version>] [--cargo <path>]');
      process.exit(0);
    } else throw new Error(`未知参数: ${current}`);
  }
  return args;
}

// 定位仓库根目录与 Cargo.toml：脚本位于 <root>/scripts/ 下
function resolveRoot() {
  const scriptDir = dirname(new URL(import.meta.url).pathname);
  return resolve(scriptDir, '..');
}

function findCargo(root, explicit) {
  if (explicit) {
    const path = resolve(root, explicit);
    if (!existsSync(path)) throw new Error(`找不到 Cargo.toml: ${explicit}`);
    return path;
  }
  for (const rel of CANDIDATES) {
    const path = join(root, rel);
    if (existsSync(path)) return path;
  }
  throw new Error(`在 ${CANDIDATES.join(' / ')} 中都找不到 Cargo.toml`);
}

// 只改 [package] 段内的 version，避免误伤依赖版本
function readPackageVersion(lines) {
  const sectionStart = lines.findIndex((line) => /^\[package\]\s*$/.test(line));
  if (sectionStart === -1) throw new Error('Cargo.toml 缺少 [package] 段');
  const sectionEnd = lines.findIndex((line, index) => index > sectionStart && /^\[/.test(line));
  const limit = sectionEnd === -1 ? lines.length : sectionEnd;
  for (let i = sectionStart + 1; i < limit; i += 1) {
    const matched = lines[i].match(/^\s*version\s*=\s*"([^"]+)"/);
    if (matched) return { value: matched[1], lineIndex: i };
  }
  throw new Error('Cargo.toml 的 [package] 段内缺少 version');
}

function gitAdd(root, path) {
  try {
    execFileSync('git', ['add', path], { cwd: root, stdio: 'pipe' });
    console.log(`已 git add ${path}`);
  } catch {
    console.log(`跳过 git add（${root} 不是 git 仓库或 git 不可用）`);
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = resolveRoot();

  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const packageVersion = pkg.version;
  if (!packageVersion) throw new Error('package.json 缺少 version');

  const cargoPath = findCargo(root, args.cargo);
  const cargoRel = cargoPath.slice(root.length + 1);
  const original = readFileSync(cargoPath, 'utf8');
  const lines = original.split('\n');
  const { value: cargoVersion, lineIndex } = readPackageVersion(lines);

  const mismatches = [];
  if (cargoVersion !== packageVersion) {
    mismatches.push(`${cargoRel} 中的 version = ${cargoVersion} ≠ package.json = ${packageVersion}`);
  }
  if (args.expect && args.expect !== packageVersion) {
    mismatches.push(`期望版本 = ${args.expect} ≠ package.json = ${packageVersion}`);
  }

  if (mismatches.length === 0) {
    console.log(`版本一致: ${packageVersion}（${cargoRel}）`);
    return;
  }

  if (args.check) {
    for (const line of mismatches) console.error(`版本不一致: ${line}`);
    console.error('运行 `npm run sync-version` 自动对齐后重试');
    process.exit(1);
  }

  // 写入模式：只重写那行 version，保留其余内容与行尾
  const indent = lines[lineIndex].match(/^\s*/)[0];
  lines[lineIndex] = `${indent}version = "${packageVersion}"`;
  writeFileSync(cargoPath, lines.join('\n'));
  console.log(`已把 ${cargoRel} 的版本从 ${cargoVersion} 改为 ${packageVersion}`);
  gitAdd(root, cargoRel);

  for (const line of mismatches) {
    if (!line.startsWith('Cargo.toml')) console.error(`注意: ${line}`);
  }
}

try {
  main();
} catch (error) {
  console.error(`版本同步失败: ${error.message}`);
  process.exit(1);
}
