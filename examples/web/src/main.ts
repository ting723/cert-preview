// 网页端演示：从 TypeScript 引用 cert-preview 公共包。
//
// 关键引用点：
//   import { load, CertViewError } from "cert-preview";
//   import type { Report } from "cert-preview";
//
// 浏览器目标需要异步 init() 一次；之后所有调用都是同步的。
import { load, CertViewError } from "cert-preview";
import type { Report } from "cert-preview";

// 演示样本内联为字符串常量（见 ./samples.ts），避免依赖 Vite 的 dev 服务器
// fs 权限——跨目录 `?raw` 导入在某些 Vite 配置下会触发 403，导致整页静默失效。
// 内联写法在 dev / build / file:// 下都 100% 可用。
import {
  chainPem,
  leafPem,
  chainIncompletePem,
  rsaLeafPem,
  ecLeafPem,
  rootPem,
  rsaKeyPem,
  encryptedKeyPem,
  ed25519PubPem,
  leafDerBase64,
} from "./samples";

const enc = new TextEncoder();

const $ = (id: string) => document.getElementById(id) as HTMLElement;
const out = (s: string) => {
  ($("output") as HTMLPreElement).textContent = s;
};

// 在模块加载失败时，把错误显式显示到输出区，而不是让整页静默失效。
function fatal(message: string): void {
  out(message);
  const banner = $("fatal");
  if (banner) {
    banner.textContent = "初始化失败：请通过本地服务器打开（如 `npm run dev` / `npm run preview`），不要直接用 file:// 打开。";
    (banner as HTMLElement).style.display = "block";
  }
}

// 整段初始化包进一个受保护的异步启动函数：WASM 加载或任一依赖失败都只会
// 显示可读提示，不会再让页面“看起来没有任何反应”。
async function bootstrap(): Promise<void> {
  // 初始化 WASM（只此一次）。
  const view = await load();

  // DER 二进制样本：从内联 base64 解码（无需任何网络请求，始终可用）。
  const leafDerBytes = Uint8Array.from(atob(leafDerBase64), (c) => c.charCodeAt(0));

  interface Scenario {
    name: string;
    pem?: string; // PEM / 文本样本
    der?: boolean; // 使用二进制 DER 样本
    hostname?: string;
  }

  const scenarios: Scenario[] = [
    { name: "完整证书链 chain.pem", pem: chainPem },
    { name: "单叶子证书 leaf.pem（无链）", pem: leafPem },
    { name: "不完整链 chain-incomplete.pem", pem: chainIncompletePem },
    { name: "RSA 叶子 · SAN 匹配 rsa-leaf.pem", pem: rsaLeafPem, hostname: "www.example.com" },
    { name: "RSA 叶子 · 主机名不匹配", pem: rsaLeafPem, hostname: "mail.example.org" },
    { name: "EC 证书 ec-leaf.pem", pem: ecLeafPem },
    { name: "自签发根 CA root.pem", pem: rootPem },
    { name: "RSA 私钥（仅元数据）rsa-2048.pkcs8.pem", pem: rsaKeyPem },
    { name: "加密私钥 rsa-2048.encrypted.pem", pem: encryptedKeyPem },
    { name: "Ed25519 公钥", pem: ed25519PubPem },
    { name: "DER 二进制 leaf.der", der: true },
  ];

  let usingDer = false;

  function currentInput(): Uint8Array {
    if (usingDer) return leafDerBytes;
    return enc.encode(($("input") as HTMLTextAreaElement).value);
  }

  function optsFromDom(): { hostname?: string; now?: number } {
    const host = (($("hostname") as HTMLInputElement).value).trim();
    const nowRaw = (($("now") as HTMLInputElement).value).trim();
    const opts: { hostname?: string; now?: number } = {};
    if (host) opts.hostname = host;
    if (nowRaw) {
      const n = Number(nowRaw);
      if (!Number.isNaN(n)) opts.now = n;
    }
    return opts;
  }

  // 渲染示例下拉框，并把选中样本填入文本框。
  function buildScenarioPicker(): void {
    const sel = $("scenario") as HTMLSelectElement;
    for (const s of scenarios) {
      const opt = document.createElement("option");
      opt.value = s.name;
      opt.textContent = s.name;
      sel.appendChild(opt);
    }
    sel.addEventListener("change", () => loadScenario(sel.value));
    loadScenario(scenarios[0].name);
  }

  function loadScenario(name: string): void {
    const s = scenarios.find((x) => x.name === name);
    if (!s) return;
    usingDer = s.der === true;
    const ta = $("input") as HTMLTextAreaElement;
    ta.value = s.pem ?? "";
    ta.disabled = usingDer;
    ($("hostname") as HTMLInputElement).value = s.hostname ?? "";
  }

  // --- 事件绑定：逐一调用四个公共方法 + 错误分支 -------------------------
  ($("btn-inspect") as HTMLButtonElement).addEventListener("click", () => {
    const report: Report = view.inspect(currentInput(), optsFromDom());
    out(JSON.stringify(report, null, 2));
  });

  ($("btn-json") as HTMLButtonElement).addEventListener("click", () => {
    out(view.inspectJson(currentInput(), optsFromDom()));
  });

  ($("btn-text") as HTMLButtonElement).addEventListener("click", () => {
    out(view.inspectText(currentInput(), optsFromDom()));
  });

  ($("btn-table") as HTMLButtonElement).addEventListener("click", () => {
    out(view.inspectTable(currentInput(), optsFromDom()));
  });

  ($("btn-error") as HTMLButtonElement).addEventListener("click", () => {
    try {
      // 注意：错误输入下 `now` 必填（wasm 目标无系统时钟），这里显式给固定值。
      view.inspect(enc.encode("这显然不是证书"), { now: 1_717_200_000 });
      out("未抛出错误（不符合预期）");
    } catch (e) {
      if (e instanceof CertViewError) {
        // 结构化错误：可据稳定 code 分支，而非匹配文案。
        out(`CertViewError\n  code   : ${e.code}\n  offset : ${e.offset}\n  message: ${e.message}`);
      } else {
        throw e;
      }
    }
  });

  buildScenarioPicker();
}

bootstrap().catch((e) => {
  console.error(e);
  fatal(`启动失败：${e instanceof Error ? e.message : String(e)}`);
});
