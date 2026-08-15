# cert-preview 示例与演示

本目录包含“把公共 API 用一遍”的全部可运行示例。它们都基于同一套 Rust 核心
（编译为 WebAssembly），因此浏览器、Node、CLI、Rust 库**输出完全一致**。详细
设计文档见 [`../docs/USAGE.md`](../docs/USAGE.md)。

## 示例总览

| 示例 | 平台 | 引用入口 | 运行方式 |
| --- | --- | --- | --- |
| `web/` | 浏览器 (WASM) | `import { load } from "cert-preview"` | `cd examples/web && npm install && npm run dev` |
| `react/` | 浏览器 (WASM + React) | `<CertViewer>` 组件 | `cd examples/react && npm install && npm run dev` |
| `standalone/` | 浏览器 (WASM, 零构建) | `importmap` 直接加载 wasm | `node examples/standalone/serve.mjs` |
| `node/inspect.ts` | Node.js (WASM) | `load` / `CertViewError` | `npx tsx examples/node/inspect.ts` |
| `../crates/cert-core/examples/inspect.rs` | Rust 库 | `detect` / `parse_bundle` / `verify_report` / `format::*` | `cargo run -p cert-core --example inspect -- fixtures/certs/chain.pem` |
| `../crates/cert-cli` | 命令行 CLI | `certview` 二进制 | `cargo run -p cert-cli -- fixtures/certs/chain.pem --format json` |

> 三个浏览器示例（web / react / standalone）都需要先生成 WASM 产物：
> ```bash
> npm --prefix packages/cert-preview run build:wasm
> ```

## 各示例说明

### 1. 网页端标准示例 `examples/web/`（原生 TS + Vite）
最薄的“在 TS 里引用公共包”示例：下拉选示例 → 调用 `inspect` / `inspectJson` /
`inspectText` / `inspectTable` 四个方法 → 渲染输出。样本内联为字符串常量，避免
依赖 dev 服务器的跨目录 `?raw` 导入（某些 Vite 配置下会 403）。

```bash
cd examples/web && npm install && npm run dev      # 开发预览 http://localhost:5173/
npm run build && npm run preview                    # 生产构建 + 预览
```

### 2. React 组件示例 `examples/react/`（React + Vite）
展示如何把 `cert-preview` 封装为**可复用的 React 组件**：
- `<CertViewer report={report} />`：把结构化 `Report` 渲染为卡片（有效期徽章、
  SAN 标签、链完整性、诊断等）。
- `<CertPlayground />`：交互式 playground（示例下拉、文本框、主机名 / now 输入、
  四个方法 + 错误分支切换）。
- 覆盖 11 个场景，含自签发根、不完整链、主机名不匹配等。

```bash
cd examples/react && npm install && npm run dev     # http://localhost:5174/
npm run build && npm run preview
```

### 3. 零构建纯浏览器示例 `examples/standalone/`（importmap，无需打包器）
不使用 Vite / webpack：直接用浏览器原生 ESM + `importmap` 加载已编译的
WebAssembly，并通过一个极简静态服务器读取 fixtures 与 wasm。这是把本库接进
任意前端工程最薄的一条路径。

```bash
node examples/standalone/serve.mjs                  # http://localhost:4321/
```
> 浏览器禁止 `file://` 拉取 wasm，所以必须经由该本地服务器打开。

### 4. Node.js 示例 `examples/node/inspect.ts`
遍历 Node loader 的全部公共方法（含 `CertViewError` 结构化错误）。需 `tsx`：
```bash
npx tsx examples/node/inspect.ts
```

### 5. Rust 库示例 `crates/cert-core/examples/inspect.rs`
服务端 / 嵌入式场景，直接调用核心库（无 WASM）：
```bash
cargo run -p cert-core --example inspect -- fixtures/certs/chain.pem
```

### 6. 命令行 CLI `crates/cert-cli`
```bash
cargo run -p cert-cli -- fixtures/certs/chain.pem --format json
cargo run -p cert-cli -- fixtures/certs/rsa-leaf.pem --format text --hostname www.example.com
```

## 覆盖的场景

- 完整证书链（chain.pem）
- 单叶子证书（无链，leaf.pem）
- 不完整链 → 诊断提示（chain-incomplete.pem）
- 主机名 / SAN 匹配（rsa-leaf.pem，`*.example.com`）
- 主机名不匹配（rsa-leaf.pem + `mail.example.org`）
- EC 证书算法细节（ec-leaf.pem，prime256v1）
- 自签发根 CA（root.pem）
- 私钥元数据（仅元数据，不含密钥材料，rsa-2048.pkcs8.pem）
- 加密私钥（rsa-2048.encrypted.pem）
- Ed25519 公钥（ed25519.spki.pem）
- 原始 DER / Base64 输入（leaf.der）
- 固定时间点评估（`--now` / `now` 选项）
- 错误输入 → 结构化 `CertViewError`
