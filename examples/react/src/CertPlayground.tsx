import { useState } from "react";
import { CertViewError } from "cert-preview";
import type { CertViewApi, Report } from "cert-preview";
import { CertViewer } from "./CertViewer";
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

interface Scenario {
  name: string;
  pem?: string;
  der?: boolean;
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
  { name: "RSA 私钥（仅元数据）", pem: rsaKeyPem },
  { name: "加密私钥", pem: encryptedKeyPem },
  { name: "Ed25519 公钥", pem: ed25519PubPem },
  { name: "DER 二进制 leaf.der", der: true },
];

type Result = { report: Report; json: string; text: string; table: string };
type Tab = "structured" | "json" | "text" | "table" | "error";

export function CertPlayground({ view }: { view: CertViewApi }) {
  const [selected, setSelected] = useState(scenarios[0].name);
  const [input, setInput] = useState(scenarios[0].pem ?? "");
  const [usingDer, setUsingDer] = useState(false);
  const [hostname, setHostname] = useState("");
  const [nowRaw, setNowRaw] = useState("");
  const [tab, setTab] = useState<Tab>("structured");
  const [result, setResult] = useState<Result | null>(null);
  const [err, setErr] = useState<{ code: string; offset: number | null; message: string } | null>(null);

  const enc = new TextEncoder();

  function currentBytes(): Uint8Array {
    if (usingDer) return Uint8Array.from(atob(leafDerBase64), (c) => c.charCodeAt(0));
    return enc.encode(input);
  }

  function opts(): { hostname?: string; now?: number } {
    const o: { hostname?: string; now?: number } = {};
    const h = hostname.trim();
    if (h) o.hostname = h;
    const n = Number(nowRaw.trim());
    if (nowRaw.trim() && !Number.isNaN(n)) o.now = n;
    return o;
  }

  function selectScenario(name: string): void {
    const s = scenarios.find((x) => x.name === name);
    if (!s) return;
    setSelected(name);
    setUsingDer(s.der === true);
    setInput(s.pem ?? "");
    setHostname(s.hostname ?? "");
  }

  function run(): void {
    try {
      const b = currentBytes();
      const o = opts();
      const report = view.inspect(b, o);
      setResult({
        report,
        json: view.inspectJson(b, o),
        text: view.inspectText(b, o),
        table: view.inspectTable(b, o),
      });
      setErr(null);
      setTab("structured");
    } catch (e) {
      if (e instanceof CertViewError) {
        setErr({ code: e.code, offset: e.offset, message: e.message });
      } else {
        setErr({ code: "UNKNOWN", offset: null, message: String(e) });
      }
      setResult(null);
      setTab("error");
    }
  }

  // 主动用非法输入触发 CertViewError，演示结构化的错误分支（可据 code 分支）。
  function triggerError(): void {
    try {
      view.inspect(enc.encode("这显然不是证书"), { now: 1_717_200_000 });
      setErr({ code: "UNKNOWN", offset: null, message: "未抛错（不符合预期）" });
    } catch (e) {
      if (e instanceof CertViewError) {
        setErr({ code: e.code, offset: e.offset, message: e.message });
      } else {
        setErr({ code: "UNKNOWN", offset: null, message: String(e) });
      }
    }
    setResult(null);
    setTab("error");
  }

  return (
    <div className="playground">
      <section className="controls">
        <h2>1 · 输入</h2>
        <label className="row">
          <span>示例</span>
          <select id="scenario" value={selected} onChange={(e) => selectScenario(e.target.value)}>
            {scenarios.map((s) => (
              <option key={s.name} value={s.name}>
                {s.name}
              </option>
            ))}
          </select>
        </label>
        <textarea
          value={input}
          disabled={usingDer}
          onChange={(e) => setInput(e.target.value)}
          rows={10}
          placeholder="粘贴 PEM / 文本，或选择上方示例"
        />
        <label className="row">
          <span>主机名（可选）</span>
          <input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="如 www.example.com" />
        </label>
        <label className="row">
          <span>now 秒（可选）</span>
          <input value={nowRaw} onChange={(e) => setNowRaw(e.target.value)} placeholder="留空=当前时间" />
        </label>
        <button className="run" onClick={run}>
          解析（调用四个公共方法）
        </button>
        <button className="run-ghost" onClick={triggerError}>
          错误示例（触发 CertViewError）
        </button>
      </section>

      <section className="output">
        <h2>2 · 输出</h2>
        <div className="tabs">
          {(
            [
              ["structured", "结构化"],
              ["json", "JSON"],
              ["text", "文本"],
              ["table", "表格"],
              ["error", "错误分支"],
            ] as [Tab, string][]
          ).map(([t, label]) => (
            <button
              key={t}
              className={tab === t ? "tab tab-active" : "tab"}
              onClick={() => setTab(t)}
            >
              {label}
            </button>
          ))}
        </div>

        {tab === "structured" && result && <CertViewer report={result.report} />}
        {tab === "json" && result && <pre className="raw">{result.json}</pre>}
        {tab === "text" && result && <pre className="raw">{result.text}</pre>}
        {tab === "table" && result && <pre className="raw">{result.table}</pre>}
        {tab === "error" && err && (
          <pre className="raw err">
{`CertViewError
  code   : ${err.code}
  offset : ${err.offset}
  message: ${err.message}`}
          </pre>
        )}
        {tab !== "error" && !result && <p className="hint">点击「解析」查看输出。结构化视图由 &lt;CertViewer&gt; 组件渲染。</p>}
      </section>
    </div>
  );
}
