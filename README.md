<div align="center">

  <h1><code>cert-preview</code></h1>

  <strong>中文：</strong>X.509 证书与密钥的结构化检查工具 —— 同一套 Rust 核心编译为 WebAssembly，CLI / 服务端 / 浏览器 / Node 四端输出完全一致。<br/>
  <strong>EN：</strong>X.509 certificate & key inspection, compiled to WebAssembly from one shared Rust core — identical output across CLI, server, browser, and Node.

</div>

## 它能做什么 · What it does

**中文** — `cert-preview` 解析 PEM / DER / Base64 形式的证书、公钥与私钥文件，**只做结构校验**，不做密码学签名验证：

- 解析主体名、签发者、序列号、有效期、公钥算法与指纹；
- 识别证书链是否能被内部自签根闭合（标出链不完整 / 自签发）；
- 给定主机名时，按 RFC 6125 匹配 SAN（含通配符规则）；
- 以三种等价格式渲染：`text` / `table` / `json`（对象或字符串）；
- 私钥仅暴露**元数据**（类型、长度、是否加密），绝不泄露密钥材料。

> **刻意不做的事**：不验证签名。签名验证需要完整的密码学栈（会显著增大 WASM 产物），且容易让人误以为这是一个"信任决策引擎"。本工具定位为离线、可复现的**结构检查器**。

**EN** — `cert-preview` parses certificates, public keys, and private keys in PEM / DER / Base64 form and performs **structural validation only** — it does *not* verify cryptographic signatures:

- Parses subject, issuer, serial number, validity, public-key algorithm, and fingerprints;
- Detects whether a chain closes onto an in-bundle self-signed root (flags incomplete / self-issued chains);
- Given a hostname, matches SANs per RFC 6125 (including wildcard rules);
- Renders in three equivalent formats: `text` / `table` / `json` (object or string);
- For private keys it exposes **metadata only** (type, size, encrypted?) — never the key material.

> **Deliberately out of scope**: no signature verification. That would require a full crypto stack (inflating the WASM binary) and risks being mistaken for a "trust engine". This tool is an offline, reproducible **structural inspector**.

## 架构：一套核心，四端同源 · Architecture: one core, four ports

```text
input   字节       → 带标签的 DER 对象（PEM 扫描 / 格式嗅探）
parse   DER        → 统一模型（x509、密钥、扩展）
verify  模型 + 时间 → 报告（有效期、链、主机名）
format  模型        → text / table / json 渲染
encode  字节        → 指纹、PEM
```

**中文** — `cert-core`（Rust）提供 `parse + verify + format`，CLI、服务端库、浏览器与 Node 全部构建在其上，**因此四端输出不可能分叉**。WASM 只是把这套核心暴露给 JS 运行时。

**EN** — `cert-core` (Rust) provides `parse + verify + format`; the CLI, server library, browser, and Node all build on top of it, so **the four ports can never diverge**. WASM merely exposes that core to JS runtimes.

## 快速开始 · Quick start

### 0. 生成 WebAssembly 产物（四端共享前置） · Build the WASM artifacts (shared prerequisite)

```bash
# 前置：Rust 工具链 + wasm32 目标 + wasm-pack
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# 浏览器目标（pkg-web/，需异步 init）
npm --prefix packages/cert-preview run build:wasm:web

# Node 目标（pkg-node/，导入即同步实例化）
npm --prefix packages/cert-preview run build:wasm:node

# 或一次性生成两者
npm --prefix packages/cert-preview run build:wasm
```

### 1. 命令行 CLI

```bash
cargo build -p cert-cli

# 多文件 + 表格
certview fixtures/certs/chain.pem fixtures/certs/rsa-leaf.pem -f table

# 标准输入 + 文本 + 主机名匹配
cat fixtures/certs/rsa-leaf.pem | certview --format text -H www.example.com

# 固定时间点 + JSON（--now 为 Unix 秒）
certview fixtures/certs/chain.pem --now 1717200000 -f json

# 仓库内快速试用
cargo run -p cert-cli -- fixtures/certs/chain.pem -f table
```

选项：`-f/--format <text|table|json>`、`-H/--hostname <HOST>`、`--now <SECONDS>`（省略 FILES 时从标准输入读取）。

Options: `-f/--format <text|table|json>`, `-H/--hostname <HOST>`, `--now <SECONDS>` (reads from stdin when FILES are omitted).

### 2. Node.js（WASM）

`nodejs` 目标在导入时**同步实例化**，无需 `init()`；`load()` 返回的 API 全是同步方法。

The `nodejs` target instantiates **synchronously at import time** — no `init()` needed; the API returned by `load()` is fully synchronous.

```bash
# 在仓库根安装 tsx（用于运行带 .ts 扩展名的示例）
npm install tsx

node --import tsx examples/node/inspect.ts
# 或更直接：
./node_modules/.bin/tsx examples/node/inspect.ts
```

```ts
import { readFileSync } from "node:fs";
import { load } from "cert-preview/node";
import { CertViewError } from "cert-preview/node";

const view = await load();                       // 同步实例化，立即就绪
const chain = new Uint8Array(readFileSync("fixtures/certs/chain.pem"));
const now = 1_717_200_000;                        // 2024-06-01，固定时钟便于复现

view.inspect(chain, { now });                     // 类型化 Report 对象
view.inspectJson(chain, { now });                 // 美化 JSON 字符串
view.inspectText(chain, { now });                 // 多段文本报告
view.inspectTable(chain, { now });                // 等宽链表格
```

### 3. 浏览器（打包器，如 Vite） · Browser (bundler, e.g. Vite)

浏览器 `web` 目标需要**一次异步 `init()`**，之后所有调用同步。

The browser `web` target requires **one async `init()`**; every call after that is synchronous.

```bash
npm --prefix packages/cert-preview run build:wasm:web   # 先生成 pkg-web/
cd examples/web
npm install
npm run dev      # 打开提示的地址（默认 http://localhost:5173/）
```

```ts
import { load, CertViewError } from "cert-preview";      // 默认即浏览器 loader
import type { Report } from "cert-preview";

const view = await load();                                // 异步初始化一次
const enc = new TextEncoder();

// now 省略时 loader 自动用 Date.now()/1000 兜底（wasm32 无系统时钟）
const report: Report = view.inspect(enc.encode(pemString), { hostname: "www.example.com" });
console.log(report.bundle.items.length);

// 错误分支：结构化 CertViewError，可据 code 分支
try {
  view.inspect(enc.encode("这不是证书"));
} catch (e) {
  if (e instanceof CertViewError) {
    console.log(e.code, e.offset, e.message);
    // e.code 例："UNKNOWN_FORMAT"
  } else throw e;
}
```

### 4. 浏览器（零构建 importmap） · Browser (zero-build importmap)

不想引入打包器时，用浏览器原生 ESM + `importmap` 直接加载已编译的 WASM：

When you don't want a bundler, use native browser ESM + `importmap` to load the compiled WASM directly:

```html
<script type="importmap">
  { "imports": { "cert_wasm": "/packages/cert-preview/pkg-web/cert_wasm.js" } }
</script>
<script type="module">
  import init, { inspectJson, inspect, inspectText, inspectTable } from "cert_wasm";
  await init();                                  // 浏览器目标需异步初始化一次
  const json = inspectJson(pemBytes, BigInt(Date.now() / 1000), "www.example.com");
</script>
```

```bash
node examples/standalone/serve.mjs              # http://localhost:4321/
```

> 浏览器禁止 `file://` 拉取 wasm，必须经本地 http 服务器。`serve.mjs` 根目录指向仓库根，既能加载 `pkg-web/` 下的 wasm，也能读取 `fixtures/` 下的样本。

> Browsers forbid loading wasm over `file://` — you must use a local http server. `serve.mjs` serves the repo root, so it can load the wasm under `pkg-web/` and read fixtures from `fixtures/`.

## 公共 API · Public API

所有 JS 端入口都来自 `load()`：

All JS entry points come from `load()`:

```ts
interface InspectOptions {
  now?: number;        // Unix 秒，用于有效期评估；省略时取当前时间
  hostname?: string;   // 匹配 SAN 的主机名
}

interface CertViewApi {
  inspect(input: Uint8Array, opts?: InspectOptions): Report;     // 类型化对象
  inspectJson(input: Uint8Array, opts?: InspectOptions): string; // JSON 字符串
  inspectText(input: Uint8Array, opts?: InspectOptions): string; // 文本
  inspectTable(input: Uint8Array, opts?: InspectOptions): string;// 表格
}
```

- 输入是**原始字节**：PEM 文本、DER 二进制或 Base64 都行，但文本需先 `new TextEncoder().encode(...)`。
- 四个方法共享同一份 `Report`，只是渲染形态不同。
- `CertViewError`（`code` / `offset` / `message` / `payload`）是跨端统一的错误类型；非法输入不会崩溃，而是抛带 `code` 的可分支错误。

- Input is **raw bytes**: PEM text, DER binary, or Base64 all work, but text must be `new TextEncoder().encode(...)`-ed first.
- All four methods share one `Report`, differing only in rendering.
- `CertViewError` (`code` / `offset` / `message` / `payload`) is the cross-port error type; bad input throws a branchable, `code`-tagged error instead of crashing.

`Report` 是嵌套模型（字段与 Rust 一一对应，由 ts-rs 生成）：

`Report` is a nested model (fields 1:1 with Rust, generated by ts-rs):

```ts
type Report = {
  bundle: Bundle;          // 解析结果（与时钟无关，可快照比对）
  evaluatedAt: number;     // 评估所用时钟（Unix 秒）
  certificates: CertificateStatus[]; // 每张证书的校验状态
};

type Bundle = {
  sourceFormat: "PEM" | "DER" | "BASE64";
  items: BundleItem[];     // 判别联合：certificate | publicKey | privateKey | unsupported
  chains: ChainSummary[];  // 链是否闭合、是否抵达自签根
  diagnostics: Diagnostic[];
};
```

代表性输出（`inspect()` 返回值，节选）：

Representative output (return value of `inspect()`, excerpt):

```json
{
  "bundle": {
    "sourceFormat": "PEM",
    "items": [
      {
        "kind": "certificate",
        "version": 3,
        "subject": { "rfc4514": "CN=www.example.org" },
        "issuer": { "rfc4514": "CN=Example Issuing CA" },
        "serialNumber": "28:2a:dd:41:...",
        "validity": { "notBefore": 1717214400, "notAfter": 1767244800 },
        "publicKey": { "algorithm": { "name": "rsaEncryption" }, "keySizeBits": 2048 },
        "signatureAlgorithm": { "name": "sha256WithRSAEncryption" },
        "fingerprints": { "sha256": "ab:cd:..." },
        "extensions": { "subjectAltNames": ["DNS:*.example.org"] },
        "selfIssued": false
      }
    ],
    "chains": [{ "complete": false, "reachesSelfSignedRoot": false }],
    "diagnostics": []
  },
  "evaluatedAt": 1717200000,
  "certificates": [
    {
      "validity": { "state": "valid", "secondsRemaining": 50040000 },
      "hostname": { "matched": true, "matchedName": "DNS:*.example.org" }
    }
  ]
}
```

> 注意：Rust 端 `Option` 字段为 `None` 时，ts-rs 会**省略**该字段，运行时表现为 `undefined`。例如无 SAN 的证书，`extensions.subjectAltNames` 不会出现；SAN 不匹配时 `hostname.matched` 为 `false`。

> Note: when a Rust `Option` field is `None`, ts-rs **omits** it, so it appears as `undefined` at runtime. E.g. a cert without SANs has no `extensions.subjectAltNames`; a non-matching hostname has `hostname.matched === false`.

## 示例集合 · Examples

更多可运行 demo（含 React 组件、零构建 importmap、Node、Rust 示例）见：

More runnable demos (React component, zero-build importmap, Node, Rust) are under:

- **[`examples/README.md`](examples/README.md)** —— 6 个示例的上手命令与场景清单 / getting-started commands and scenario list for 6 examples
- **[`docs/USAGE.md`](docs/USAGE.md)**（中文）/ **[`docs/USAGE.en.md`](docs/USAGE.en.md)**（EN）—— 完整的场景化使用指南 / full scenario-based usage guide

## 构建与验证 · Build & verify

```bash
# Rust：解析 / 校验 / 渲染 / 快照，跨端一致性
cargo test --workspace

# Node：smoke + fixture 一致性（WASM 输出 == Rust 快照）
npm --prefix packages/cert-preview test

# 网页端：类型检查 + 生产构建
cd examples/web && npm install && npm run build
```

当前验证结果（构建时）：

Current verification results (at build time):

- Rust 测试：79 项全绿，`cargo clippy --workspace --all-targets` 零警告 / Rust: 79 tests green, `cargo clippy --workspace --all-targets` clean
- Node 测试：25 项全绿（3 smoke + 21 一致性）/ Node: 25 tests green (3 smoke + 21 consistency)
- 网页端：`tsc` 类型检查通过，`vite build` 成功 / Web: `tsc` type-check passes, `vite build` succeeds

**一致性保证**：`crates/cert-core/tests/snapshot.rs` 为每个 fixture 生成固定时钟（`2024-06-01`）的 JSON 快照；Node 一致性测试在 WASM 上跑同一输入，断言其输出与 Rust 快照语义一致。CLI / 服务端 / 浏览器 / Node 共享同一真相。

**Consistency guarantee**: `crates/cert-core/tests/snapshot.rs` snapshots every fixture at a fixed clock (`2024-06-01`); the Node consistency test runs the same input through WASM and asserts semantic equality with the Rust snapshot. CLI / server / browser / Node share one source of truth.

## 已知限制 · Limitations

- 不验证签名，仅做结构校验；不要把它当作信任锚点或合规审计工具。
  No signature verification, structural checks only — not a trust anchor or compliance auditor.
- 私钥材料在解析阶段即被丢弃，工具无法还原或导出私钥。
  Private-key material is dropped at parse time; the tool cannot recover or export a private key.
- `now` 为必填语义参数（`wasm32` 无系统时钟）；JS loader 在调用方省略时自动兜底为当前时间。
  `now` is semantically required (`wasm32` has no system clock); JS loaders default it to the current time when omitted.

## License

MIT
