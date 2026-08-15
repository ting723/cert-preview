import { useEffect, useState } from "react";
import { load } from "cert-preview";
import type { CertViewApi } from "cert-preview";
import { CertPlayground } from "./CertPlayground";

export default function App() {
  const [view, setView] = useState<CertViewApi | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    load()
      .then((v) => {
        if (alive) setView(v);
      })
      .catch((e) => {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div className="app">
      <header className="app-header">
        <h1>cert-preview · React 演示</h1>
        <p>
          同一套 Rust 内核编译为 WebAssembly，浏览器、Node、CLI 输出完全一致。
          下方演示如何在 React 中引用 <code>cert-preview</code> 公共包，并渲染结构化报告。
        </p>
      </header>

      {error && (
        <div className="fatal">
          初始化失败：{error}
          <br />
          请通过本地服务器打开（<code>npm run dev</code> / <code>npm run preview</code>），不要直接用 <code>file://</code> 打开。
        </div>
      )}
      {!error && !view && <div className="loading">正在加载 WebAssembly…</div>}
      {view && <CertPlayground view={view} />}
    </div>
  );
}
