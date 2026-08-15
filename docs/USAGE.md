# cert-preview 使用文档

> X.509 证书与密钥的结构化检查工具。同一套核心库（Rust）编译为 WebAssembly，
> 支撑命令行（CLI）、服务端库、浏览器与 Node 四端，输出完全一致。

> **English version / 英文版**：[`docs/USAGE.en.md`](USAGE.en.md)

本文档覆盖：

1. [架构与设计](#1-架构与设计)
2. [公共 API 速查](#2-公共-api-速查)
3. [场景化使用指南](#3-场景化使用指南)
4. [各平台使用方式](#4-各平台使用方式)
   - [4.1 命令行 CLI](#41-命令行-cli)
   - [4.2 Rust 库（服务端 / 嵌入式）](#42-rust-库服务端--嵌入式)
   - [4.3 Node.js（WASM）](#43-nodejswasm)
   - [4.4 浏览器（WASM）——HTML + TS 引用示例](#44-浏览器wasmhtml--ts-引用示例)
5. [零构建纯浏览器示例（importmap）](#5-零构建纯浏览器示例importmap)
6. [构建与验证](#6-构建与验证)

---

## 1. 架构与设计

```text
input   字节       → 带标签的 DER 对象（PEM 扫描 / 格式嗅探）
parse   DER        → 统一模型（x509、密钥、扩展）
verify  模型 + 时间 → 报告（有效期、链、主机名）
format  模型        → text / table / json 渲染
encode  字节        → 指纹、PEM
```

依赖严格向下指向。CLI、服务端、浏览器与 Node 全部构建在
`parse + verify + format` 同一套栈之上，**因此四端输出不可能分叉**。

**刻意不做的事**：不验证签名。签名验证需要完整的密码学栈（会显著增大 WASM
产物），且容易让人误以为这是一个“信任决策引擎”。本工具只做**结构校验**——
主体名 / 密钥标识是否对得上、是否在有效期内、主机名是否匹配 SAN。

---

## 2. 公共 API 速查

| 层 | 入口 | 说明 |
| --- | --- | --- |
| 输入 | `cert_core::input::detect(bytes)` | 嗅探 PEM / DER / Base64，返回 `SourceFormat` 与 DER 对象列表 |
| 解析 | `cert_core::parse_bundle(bytes)` | 解码为统一 `Bundle` 模型 |
| 校验 | `cert_core::verify_report(bundle, now, hostname)` | 在 `now`（Unix 秒）评估，可选 `hostname` 做 SAN 匹配，返回 `Report` |
| 渲染 | `cert_core::format::text` / `format::table` / `format::to_json` | 三种渲染器消费同一 `Report` |
| WASM | `view.inspect / inspectJson / inspectText / inspectTable` | 浏览器 / Node 调用的四个方法 |
| 错误 | `CertViewError { code, offset, message }` | 跨端统一的结构化错误，可据 `code` 分支 |

`Report` 结构（ts-rs 自动生成，Rust / TS 字段一一对应）：

```ts
type Report = {
  bundle: Bundle;          // 解析结果（与时钟无关，可快照比对）
  evaluatedAt: number;     // 评估所用时钟（Unix 秒）
  certificates: CertificateStatus[]; // 每张证书的校验状态
};
```

---

## 3. 场景化使用指南

下面每个场景都给出**四端等价**的写法。路径默认相对仓库根目录。

### 场景 A：检查完整证书链（chain.pem）

**目标**：确认证书链能否链接到自签根，并查看各级有效期。

- **CLI**：`certview fixtures/certs/chain.pem --format table`
- **Rust**：`cargo run -p cert-core --example inspect -- fixtures/certs/chain.pem`
- **Node**：`view.inspect(chain, { now })` → `report.bundle.items.length`
- **浏览器**：选择示例 “完整证书链 chain.pem”，点击 `inspectTable()`

输出（CLI，节选）：

```text
│ #   │ SUBJECT                      │ ISSUER                   │ EXPIRES      │ KEY            │ STATUS       │
│ 0   │ www.example.org              │ Example Issuing CA       │ 2025-01-01   │ rsaEncryption… │ expired      │
│ 1   │ Example Issuing CA           │ Example Root CA          │ 2034-01-01   │ rsaEncryption… │ valid        │
│ 2   │ Example Root CA              │ Example Root CA          │ 2034-01-01   │ rsaEncryption… │ valid        │
```

### 场景 B：主机名 / SAN 匹配（rsa-leaf.pem）

**目标**：给一个访问主机名（如 `www.example.com`），判断证书是否覆盖它。
该证书 SAN 为 `DNS:*.example.com`，通配符仅匹配单标签。

- **CLI**：`certview fixtures/certs/rsa-leaf.pem -H www.example.com --format json`
- **Node**：
  ```ts
  const m = view.inspect(rsaLeaf, { now, hostname: "www.example.com" })
                .certificates[0].hostname;
  console.log(m.matched, m.matchedName); // true, "DNS:*.example.com"
  ```
- **浏览器**：在 “主机名” 输入框填 `www.example.com`，点击任意渲染按钮；
  或选 “模拟错误输入” 之外的按钮后查看 `hostname` 字段。

通配符匹配遵循 RFC 6125 §6.4.3：`*.example.com` 匹配 `www.example.com`，
但**不匹配** `a.b.example.com`（多级子域）。

### 场景 C：查看算法细节（ec-leaf.pem）

**目标**：确认签名算法、公钥算法、曲线。

- **Node**：
  ```ts
  const it = report.bundle.items.find(i => i.kind === "certificate");
  it.signatureAlgorithm.name; // "ecdsa-with-SHA256"
  it.publicKey.algorithm.name; // "id-ecPublicKey"
  ```

### 场景 D：私钥元数据（仅元数据，不含密钥材料）

**目标**：检查私钥类型与长度，但**绝不泄露私钥内容**。
解析阶段就丢弃了私钥材料，渲染阶段也无从泄露。

- **CLI**：`certview fixtures/keys/rsa-2048.pkcs8.pem --format text`
- **Node**：
  ```ts
  const k = report.bundle.items.find(i => i.kind === "privateKey");
  k.format;        // "pkcs8"
  k.keySizeBits;   // 2048
  k.algorithm.name;// "rsaEncryption"
  ```

### 场景 E：加密私钥（rsa-2048.encrypted.pem）

**目标**：识别私钥被口令加密（本工具不解密，仅标注 `encrypted: true`）。

- **CLI**：`certview fixtures/keys/rsa-2048.encrypted.pem --format text`
  输出中会显示 `Encrypted: yes`。

### 场景 F：原始 DER / Base64 输入

**目标**：直接喂二进制 DER 或裸 Base64（无 PEM 头尾），工具自动嗅探。

- **DER**：`certview fixtures/certs/leaf.der --format text`
  输出（节选）：
  ```text
  === Chains ===
    www.example.org   [INCOMPLETE]
      - WARNING issuer chain does not reach a self-signed root present in the bundle
  ```
  （该单证书不在包内携带其签发者，故链标记为不完整——这正是结构校验的价值。）
- **Node / 浏览器**：`view.inspect(new Uint8Array(derBytes), { now })`，
  文本或 Base64 同样会被 `detect` 识别。

### 场景 G：在固定时间点评估有效期（--now）

**目标**：用确定时间复现结果（测试、审计、比对）。`now` 为 Unix 秒。

- **CLI**：`certview fixtures/certs/chain.pem --now 1717200000 --format table`
  （`1717200000` = 2024-06-01，此时链上叶子证书仍 `valid`。）
- **Node / 浏览器**：`view.inspect(chain, { now: 1_717_200_000 })`

> WASM 目标（`wasm32-unknown-unknown`）**没有系统时钟**，`now` 是必填参数；
> 两个 TS loader 在调用方省略 `now` 时，自动用 `Date.now() / 1000` 兜底，
> 因此 JS API 仍可写 `view.inspect(bytes)` 而不报错。

### 场景 H：错误输入 → 结构化错误

**目标**：非法输入应返回可据 `code` 分支的错误，而非崩溃。

- **CLI**：`printf 'garbage\n' | certview` → 进程退出码 **非 0**，标准错误打印原因。
- **Node / 浏览器**：
  ```ts
  try {
    view.inspect(new TextEncoder().encode("this is not a certificate"), { now });
  } catch (e) {
    if (e instanceof CertViewError) {
      console.log(e.code, e.offset, e.message);
      // UNKNOWN_FORMAT  null  "input is neither PEM text nor a DER encoded structure"
    } else throw e;
  }
  ```

---

## 4. 各平台使用方式

### 4.1 命令行 CLI

可执行文件 `certview`（来自 `crates/cert-cli`）。

```bash
# 构建
cargo build -p cert-cli

# 用法
certview [FILES...] [选项]
  -f, --format <text|table|json>   渲染格式（默认 text）
  -H, --hostname <HOST>             匹配 SAN 的主机名
      --now <SECONDS>               Unix 秒，用于有效期评估（默认当前时间）
  （省略 FILES 时从标准输入读取）
```

示例：

```bash
# 多文件 + 表格
certview fixtures/certs/chain.pem fixtures/certs/rsa-leaf.pem -f table

# 标准输入 + 文本 + 主机名匹配
cat fixtures/certs/rsa-leaf.pem | certview --format text -H www.example.com

# 固定时间点 + JSON
certview fixtures/certs/chain.pem --now 1717200000 -f json
```

在仓库内快速试用：`cargo run -p cert-cli -- fixtures/certs/chain.pem -f table`。

### 4.2 Rust 库（服务端 / 嵌入式）

在 `Cargo.toml`：

```toml
[dependencies]
cert-core = { path = "crates/cert-core", default-features = true }
```

最小用法：

```rust
use cert_core::input::detect;
use cert_core::{format, parse_bundle, verify_report};

fn inspect(bytes: &[u8]) -> cert_core::Result<()> {
    // 1) 格式嗅探
    let detected = detect(bytes)?;
    println!("format = {:?}, objects = {}", detected.format, detected.objects.len());

    // 2) 解析
    let bundle = parse_bundle(bytes)?;

    // 3) 校验（now = 当前时间；可传 hostname）
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let report = verify_report(bundle, now, Some("www.example.com"));

    // 4) 渲染（三种等价）
    println!("{}", format::text(&report));
    println!("{}", format::table(&report));
    println!("{}", format::to_json(&report)?);
    Ok(())
}
```

完整可运行示例见 `crates/cert-core/examples/inspect.rs`：

```bash
cargo run -p cert-core --example inspect -- fixtures/certs/chain.pem --hostname www.example.com
```

### 4.3 Node.js（WASM）

WASM 的 `nodejs` 目标在导入时**同步实例化**，无需 `init()`。

```bash
# 在仓库根安装 tsx（示例用 .ts 扩展名的相对 import，需 tsx 运行）
npm install tsx

# 运行示例（从仓库根）
node --import tsx examples/node/inspect.ts
# 或更直接：
./node_modules/.bin/tsx examples/node/inspect.ts
```

`examples/node/inspect.ts` 关键片段：

```ts
import { load } from "../../packages/cert-preview/src/loader-node.ts";
import { CertViewError } from "../../packages/cert-preview/src/errors.ts";
import { readFileSync } from "node:fs";

const view = await load();
const chain = new Uint8Array(readFileSync("fixtures/certs/chain.pem"));

view.inspect(chain, { now: 1_717_200_000 });   // 对象
view.inspectJson(chain, { now: 1_717_200_000 }); // JSON 字符串
view.inspectText(chain, { now: 1_717_200_000 });  // 文本
view.inspectTable(chain, { now: 1_717_200_000 }); // 表格
```

发布后消费者应写 `import { load, CertViewError } from "cert-preview/node"`。

### 4.4 浏览器（WASM）——HTML + TS 引用示例

这是本项目的**网页端标准示例**，位于 `examples/web/`。它从 TypeScript 直接
引用公共包 `cert-preview`，覆盖四个方法与错误分支。

**前置**：需先生成浏览器端 WASM 产物（首次或重新拉取后）：

```bash
npm --prefix packages/cert-preview run build:wasm:web   # 生成 pkg-web/
```

**运行**：

```bash
cd examples/web
npm install
npm run dev      # 开发服务器，浏览器打开提示的地址
npm run build    # 生产构建，输出到 examples/web/dist/
```

**`index.html`（入口）**——注意底部以 ES module 方式加载 TS：

```html
<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <title>cert-preview · 网页端演示</title>
  </head>
  <body>
    <main>
      <h1>cert-preview 网页端演示</h1>
      <textarea id="input" rows="12"></textarea>
      <button id="btn-inspect">检测对象 inspect()</button>
      <button id="btn-json">JSON</button>
      <button id="btn-text">文本</button>
      <button id="btn-table">表格</button>
      <button id="btn-error">模拟错误输入</button>
      <pre id="output"></pre>
    </main>
    <!-- 关键点：以 type="module" 加载 TypeScript 源码 -->
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>
```

**`src/main.ts`（在 TS 上引用公共包）**——这是“如何在 TS 上引用”的核心：

```ts
// 从公共包引用：浏览器默认导出即 browser loader
import { load, CertViewError } from "cert-preview";
import type { Report } from "cert-preview";

// WASM 只需异步初始化一次；之后所有调用同步
const view = await load();

const enc = new TextEncoder();

// 1) 检测对象：返回类型化 Report
document.getElementById("btn-inspect")!.addEventListener("click", () => {
  const report: Report = view.inspect(enc.encode(inputEl.value), { now: 1_717_200_000 });
  output(JSON.stringify(report, null, 2));
});

// 2) JSON 渲染
document.getElementById("btn-json")!.addEventListener("click", () => {
  output(view.inspectJson(enc.encode(inputEl.value)));
});

// 3) 文本渲染
document.getElementById("btn-text")!.addEventListener("click", () => {
  output(view.inspectText(enc.encode(inputEl.value)));
});

// 4) 表格渲染
document.getElementById("btn-table")!.addEventListener("click", () => {
  output(view.inspectTable(enc.encode(inputEl.value)));
});

// 5) 错误分支：结构化 CertViewError
document.getElementById("btn-error")!.addEventListener("click", () => {
  try {
    view.inspect(enc.encode("这不是证书"), { now: 1_717_200_000 });
  } catch (e) {
    if (e instanceof CertViewError) {
      output(`code=${e.code} offset=${e.offset} message=${e.message}`);
    } else throw e;
  }
});
```

完整文件见 `examples/web/src/main.ts`（含下拉示例、DER 二进制加载、主机名输入框等）。
构建已验证通过：`tsc` 类型检查 + `vite build` 成功，WASM（381 KB）正确打包为资源。

### 4.5 React 组件示例

若你的前端是 React，可把 `cert-preview` 封装为可复用组件。示例位于
`examples/react/`：

- `<CertViewer report={report} />`：把结构化 `Report` 渲染为卡片（有效期徽章、
  SAN 标签、链完整性、诊断等）。
- `<CertPlayground />`：交互式 playground（示例下拉、文本框、主机名 / now 输入、
  四个方法 + 错误分支切换）。

```tsx
import { load } from "cert-preview";
import type { CertViewApi } from "cert-preview";
import { CertViewer } from "./CertViewer";

export function App() {
  const [view, setView] = useState<CertViewApi | null>(null);
  useEffect(() => { load().then(setView); }, []);
  if (!view) return <p>加载 WebAssembly…</p>;
  const report = view.inspect(pemBytes, { hostname: "www.example.com" });
  return <CertViewer report={report} />;
}
```

```bash
cd examples/react && npm install && npm run dev     # http://localhost:5174/
```

---

## 5. 零构建纯浏览器示例（importmap）

若不想引入打包器，可直接用浏览器原生 ESM + `importmap` 加载已编译的
WebAssembly。完整可运行示例见 `examples/standalone/`：

```html
<script type="importmap">
  {
    "imports": {
      "cert_wasm": "/packages/cert-preview/pkg-web/cert_wasm.js"
    }
  }
</script>
<script type="module">
  import init, { inspectJson, inspect, inspectText, inspectTable } from "cert_wasm";
  await init();                       // 浏览器目标需异步初始化一次
  const json = inspectJson(pemBytes, BigInt(Date.now() / 1000), "www.example.com");
</script>
```

运行（浏览器禁止 `file://` 拉取 wasm，必须经本地服务器）：

```bash
node examples/standalone/serve.mjs   # http://localhost:4321/
```

> `serve.mjs` 是一个极简静态服务器，根目录指向仓库根，因此既能加载
> `pkg-web/` 下的 wasm，也能直接读取 `fixtures/` 下的样本证书。

---

## 6. 构建与验证

### 前置依赖

- Rust 工具链（含 `wasm32-unknown-unknown` 目标）：`rustup target add wasm32-unknown-unknown`
- `wasm-pack`：`cargo install wasm-pack`
- Node.js ≥ 18 与 npm

### 生成 WASM 产物

```bash
npm --prefix packages/cert-preview run build:wasm:web   # 浏览器（pkg-web/）
npm --prefix packages/cert-preview run build:wasm:node  # Node（pkg-node/）
# 或一次性：
npm --prefix packages/cert-preview run build:wasm
```

> 离线环境：若 `wasm-pack` 无法下载 `wasm-opt`（binaryen）优化器，会在
> `crates/cert-wasm/Cargo.toml` 的 `[package.metadata.wasm-pack.profile.release]`
> 中设置 `wasm-opt = false` 跳过，仅影响体积不影响正确性。

### 测试与一致性

```bash
# Rust：解析 / 校验 / 渲染 / 快照，跨端一致性
cargo test --workspace

# Node：smoke + 21 个 fixture 的“WASM 输出 == Rust 快照”一致性
npm --prefix packages/cert-preview test

# 网页端：类型检查 + 生产构建
cd examples/web && npm install && npm run build
```

**一致性保证**：`crates/cert-core/tests/snapshot.rs` 为每个 fixture 生成固定时钟
（`2024-06-01`）的 JSON 快照；`packages/cert-preview/test/consistency.test.ts`
在 Node 中跑同一 WASM，断言其输出与 Rust 快照语义一致。CLI / 服务端 / 浏览器
/WASM 因此共享同一真相。

### 当前验证结果（构建时）

- Rust 测试：79 项全绿，`cargo clippy --workspace --all-targets` 零警告
- Node 测试：25 项全绿（3 smoke + 21 一致性）
- 网页端：`tsc` 类型检查通过，`vite build` 成功，WASM 产物 381 KB
