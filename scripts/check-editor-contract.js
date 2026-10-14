import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(root, "native/web/editor.html"), "utf8");
const cases = JSON.parse(
  fs.readFileSync(path.join(root, "native/web/editor-contract-cases.json"), "utf8")
);
const defaults = JSON.parse(
  fs.readFileSync(path.join(root, "native/web/editor-defaults.json"), "utf8")
);
const routeCases = JSON.parse(
  fs.readFileSync(path.join(root, "native/testdata/editor-route-cases.json"), "utf8")
);
const exampleConnections = JSON.parse(
  fs.readFileSync(path.join(root, "example.config.json"), "utf8")
);
function extractSection(startMarker, endMarker, name) {
  const start = html.indexOf(startMarker);
  const end = html.indexOf(endMarker, start);
  if (
    start < 0 ||
    end < 0 ||
    start >= end ||
    start !== html.lastIndexOf(startMarker) ||
    end !== html.lastIndexOf(endMarker)
  ) {
    throw new Error(`editor.html ${name}标记缺失、重复或顺序错误`);
  }
  return html.slice(start, end);
}

const validationSource = extractSection(
  "// EDITOR_VALIDATION_START",
  "// EDITOR_VALIDATION_END",
  "前端配置校验器"
);
const routeSource = extractSection(
  "// EDITOR_ROUTE_START",
  "// EDITOR_ROUTE_END",
  "连接线路计算器"
);
const jsonCompareSource = extractSection(
  "// EDITOR_JSON_COMPARE_START",
  "// EDITOR_JSON_COMPARE_END",
  "JSON 语义比较器"
);
const context = vm.createContext({});
vm.runInContext(
  `${validationSource}; this.validateConnections = validateConnections;`,
  context
);
vm.runInContext(
  `${jsonCompareSource}; this.connectionsSemanticallyEqual = connectionsSemanticallyEqual;`,
  context
);
vm.runInContext(
  `${routeSource}; this.buildConnectionRoute = buildConnectionRoute; this.connectionEndpoint = connectionEndpoint; this.connectionTransport = connectionTransport;`,
  context
);
for (const testCase of cases) {
  context.input = JSON.stringify(testCase.connections);
  const actual = vm.runInContext("validateConnections(JSON.parse(input)).ok", context);
  if (actual !== testCase.valid) {
    throw new Error(
      `前端配置契约样例失败: ${testCase.name}，期望 ${testCase.valid}，实际 ${actual}`
    );
  }
}
context.leftConnections = [{ name: "same", host: "host", port: 22, username: "root" }];
context.rightConnections = [{ username: "root", port: 22, host: "host", name: "same" }];
if (!vm.runInContext("connectionsSemanticallyEqual(leftConnections, rightConnections)", context)) {
  throw new Error("JSON 语义比较失败: 对象键顺序不应产生修改");
}
context.rightConnections[0].host = "changed";
if (vm.runInContext("connectionsSemanticallyEqual(leftConnections, rightConnections)", context)) {
  throw new Error("JSON 语义比较失败: 字段值变化必须产生修改");
}


context.endpointItem = { username: "root", host: "server", port: 0 };
if (vm.runInContext("connectionEndpoint(endpointItem)", context) !== "root@server:0") {
  throw new Error("端点契约失败: 端口 0 不得回退为默认端口");
}
context.endpointItem = {};
context.endpointFallback = { username: "user", host: "host" };
if (vm.runInContext("connectionEndpoint(endpointItem, endpointFallback)", context) !== "user@host:22") {
  throw new Error("端点契约失败: 空值回退不一致");
}

for (const testCase of routeCases) {
  const item = testCase.connections.find(connection => connection.name === testCase.target);
  context.routeItem = item;
  context.routeItems = testCase.connections;
  const transport = JSON.parse(vm.runInContext("JSON.stringify(connectionTransport(routeItem, routeItems))", context));
  if (transport.kind !== testCase.expectedTransport) {
    throw new Error(`线路传输契约失败: ${testCase.name}，实际 ${transport.kind}`);
  }
  if (testCase.expectedJumpTransport && transport.jumpTransport !== testCase.expectedJumpTransport) {
    throw new Error(`跳板传输契约失败: ${testCase.name}，实际 ${transport.jumpTransport}`);
  }
  const route = JSON.parse(vm.runInContext("JSON.stringify(buildConnectionRoute(routeItem, routeItems))", context));
  const kinds = route.map(node => node.kind);
  if (JSON.stringify(kinds) !== JSON.stringify(testCase.expectedKinds)) {
    throw new Error(`线路展示契约失败: ${testCase.name}，实际 ${kinds.join(" -> ")}`);
  }
  if (testCase.expectedProxy && route.find(node => node.kind === "proxy")?.detail !== testCase.expectedProxy) {
    throw new Error(`线路代理显示失败: ${testCase.name}`);
  }
}

context.routeItem = {
  name: "target", host: "10.0.0.1", username: "deploy",
  privilegeEnabled: true, sudoUser: "admin", suUser: "root", suPasswordRef: "agentsshcli:target:su"
};
context.routeItems = [context.routeItem];
const privilegeRoute = JSON.parse(vm.runInContext("JSON.stringify(buildConnectionRoute(routeItem, routeItems))", context));
if (privilegeRoute.at(-1)?.kind !== "privilege" || privilegeRoute.at(-1)?.detail !== "sudo:admin · su:root") {
  throw new Error("线路提权显示失败");
}
const defaultRules = defaults.commandBlacklist;
if (!Array.isArray(defaultRules) || !defaultRules.length || defaultRules.some(rule => typeof rule !== "string")) {
  throw new Error("editor-defaults.json 的 commandBlacklist 必须是非空字符串数组");
}
for (const rule of defaultRules) {
  new RegExp(rule);
  const encodedRule = JSON.stringify(rule).slice(1, -1);
  for (const document of ["README.md", "README_EN.md", "SKILL.md"]) {
    const content = fs.readFileSync(path.join(root, document), "utf8");
    if (!content.includes(encodedRule)) {
      throw new Error(`${document} 缺少默认黑名单规则: ${rule}`);
    }
  }
  const existsInExample = exampleConnections.some(connection =>
    Array.isArray(connection.commandBlacklist) && connection.commandBlacklist.includes(rule)
  );
  if (!existsInExample) throw new Error(`example.config.json 缺少默认黑名单规则: ${rule}`);
  if (html.includes(encodedRule)) {
    throw new Error(`editor.html 不得硬编码默认黑名单规则: ${rule}`);
  }
}

// 编译整个页面脚本，并验证首次信任流程的关键异步边界。
new vm.Script(html.match(/<script>([\s\S]*?)<\/script>/)[1]);
const trustFlowSource = extractSection("    function hostTrustRequest(", "    async function testConnection()", "主机信任流程");
const challenge = { connection: "server", host: "127.0.0.1", port: 22, fingerprint: "SHA256:test" };
async function checkTrustFlow({ responses, approved = true, invalidateAt, failAt, snapshot = { connection: "server", connections: [{ name: "server", host: "127.0.0.1" }], passwordUpdates: [] } }) {
  const requests = [];
  const statuses = [];
  let valid = true;
  const flowContext = vm.createContext({
    apiRequest: async (url, options) => {
      const body = JSON.parse(options.body);
      requests.push({ url, body });
      // 按后端的连接范围约束拒绝无关草稿，避免模拟成功掩盖授权请求冲突。
      const target = body.connections.find(item => item.name === body.connection);
      if (body.passwordUpdates.some(update => update.connection !== body.connection && update.connection !== target?.jumpHost)) {
        throw new Error("临时密码只能用于当前连接或跳板机");
      }
      if (invalidateAt === requests.length) valid = false;
      if (failAt === requests.length) throw new Error("登记失败");
      return responses.shift();
    },
    confirmHostTrust: async () => {
      if (invalidateAt === "confirm") valid = false;
      return approved;
    },
    setTestStatus: (...args) => statuses.push(args)
  });
  vm.runInContext(`${trustFlowSource}; this.run = testAndTrustConnection;`, flowContext);
  let error;
  try {
    await flowContext.run(snapshot, () => valid);
  } catch (caught) { error = caught.message; }
  return { requests, statuses, error };
}
const unknown = () => ({ ok: false, unknownHostKey: challenge });
const accepted = await checkTrustFlow({ responses: [unknown(), { ok: true }, { ok: true }] });
assert.deepEqual(accepted.requests.map(item => item.url), ["/api/connections/test", "/api/connections/trust-host", "/api/connections/test"]);
assert.equal(accepted.requests[1].body.fingerprint, challenge.fingerprint);
assert.deepEqual(accepted.requests[0].body, accepted.requests[2].body);
assert.deepEqual(accepted.statuses.at(-1), ["连接成功", "success"]);
const cancelled = await checkTrustFlow({ responses: [unknown()], approved: false });
assert.equal(cancelled.requests.length, 1);
assert.match(cancelled.statuses.at(-1)[0], /已取消信任/);
for (const invalidateAt of [1, "confirm", 2]) {
  const stale = await checkTrustFlow({ responses: [unknown(), { ok: true }], invalidateAt });
  assert.equal(stale.requests.length, invalidateAt === 2 ? 2 : 1);
  assert.ok(!stale.statuses.some(([message]) => message === "连接成功"));
}
const changed = await checkTrustFlow({ responses: [{ ok: false, error: "公钥不符" }] });
assert.equal(changed.requests.length, 1);
assert.deepEqual(changed.statuses.at(-1), ["连接失败：公钥不符", "failure"]);
const failed = await checkTrustFlow({ responses: [unknown()], failAt: 2 });
assert.equal(failed.error, "登记失败");
assert.equal(failed.requests.length, 2);
const jumpSnapshot = {
  connection: "server",
  connections: [
    { name: "server", host: "127.0.0.1", jumpHost: "jump" },
    { name: "jump", host: "127.0.0.2" }
  ],
  passwordUpdates: [
    { connection: "server", password: "target-draft" },
    { connection: "jump", password: "jump-draft" }
  ]
};
const jumpBefore = structuredClone(jumpSnapshot);
const jump = await checkTrustFlow({ responses: [{ ok: false, unknownHostKey: { ...challenge, connection: "jump" } }, { ok: true }, unknown(), { ok: true }, { ok: true }], snapshot: jumpSnapshot });
assert.equal(jump.error, undefined);
assert.equal(jump.requests[1].body.connection, "jump");
assert.deepEqual(jump.requests[1].body.passwordUpdates, [jumpBefore.passwordUpdates[1]]);
assert.equal(jump.requests[3].body.connection, "server");
assert.deepEqual(jump.requests[3].body.passwordUpdates, jumpBefore.passwordUpdates);
assert.deepEqual(jump.requests[0].body, jump.requests[2].body);
assert.deepEqual(jump.requests[0].body, jump.requests[4].body);
assert.deepEqual(jumpSnapshot, jumpBefore);
assert.deepEqual(jump.statuses.at(-1), ["连接成功", "success"]);
const targetDraftOnly = await checkTrustFlow({
  responses: [{ ok: false, unknownHostKey: { ...challenge, connection: "jump" } }, { ok: true }, { ok: true }],
  snapshot: { ...jumpBefore, passwordUpdates: [jumpBefore.passwordUpdates[0]] }
});
assert.equal(targetDraftOnly.error, undefined);
assert.deepEqual(targetDraftOnly.requests[1].body.passwordUpdates, []);
assert.deepEqual(targetDraftOnly.requests[2].body.passwordUpdates, [jumpBefore.passwordUpdates[0]]);
assert.deepEqual(targetDraftOnly.statuses.at(-1), ["连接成功", "success"]);
console.log(`编辑器前端配置契约检查通过（${cases.length} 个样例，含主机信任流程）`);
