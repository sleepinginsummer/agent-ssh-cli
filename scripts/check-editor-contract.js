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

console.log(`编辑器前端配置契约检查通过（${cases.length} 个样例）`);
