import type { ReactNode } from "react";
import type {
  Report,
  CertificateStatus,
  CertificateInfo,
  PrivateKeyInfo,
  PublicKeyInfo,
  ValidityStatus,
  ChainSummary,
  Diagnostic,
  BundleItem,
} from "cert-preview";

function fmtDate(unix: number): string {
  return new Date(unix * 1000).toISOString().replace(".000Z", "Z");
}

type Tone = "ok" | "warn" | "bad" | "info";

function Badge({ children, tone }: { children: ReactNode; tone: Tone }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <span className="field-label">{label}</span>
      <span className="field-value">{children}</span>
    </div>
  );
}

function Diag({ d }: { d: Diagnostic }) {
  const tone: Tone = d.level === "error" ? "bad" : d.level === "warning" ? "warn" : "info";
  return (
    <div className={`diag diag-${tone}`}>
      <span className="diag-code">{d.code}</span>
      <span className="diag-msg">{d.message}</span>
    </div>
  );
}

function validityTone(v: ValidityStatus): Tone {
  switch (v.state) {
    case "valid":
      return "ok";
    case "expired":
      return "bad";
    case "notYetValid":
      return "warn";
    default:
      return "info";
  }
}

function CertCard({ c, status }: { c: CertificateInfo; status?: CertificateStatus }) {
  const v = status?.validity;
  const host = status?.hostname ?? null;
  const alg = c.publicKey.algorithm.name + (c.publicKey.curve ? ` · ${c.publicKey.curve}` : "");
  const ks = c.publicKey.keySizeBits ? ` ${c.publicKey.keySizeBits} bit` : "";
  return (
    <div className="card">
      <div className="card-head">
        <span className="kind kind-cert">CERTIFICATE</span>
        {v && <Badge tone={validityTone(v)}>{v.state} · 剩余 {v.secondsRemaining}s</Badge>}
        {host && (
          <Badge tone={host.matched ? "ok" : "bad"}>
            {host.matched ? `SAN 匹配 ${host.matchedName ?? ""}` : `主机名不匹配 ${host.hostname}`}
          </Badge>
        )}
        {c.selfIssued && <Badge tone="warn">自签发</Badge>}
      </div>
      <Field label="主体 Subject"><code>{c.subject.rfc4514}</code></Field>
      <Field label="签发者 Issuer"><code>{c.issuer.rfc4514}</code></Field>
      <Field label="版本">v{c.version}</Field>
      <Field label="序列号"><code>{c.serialNumber}</code></Field>
      <Field label="有效期">
        {fmtDate(c.validity.notBefore)} → {fmtDate(c.validity.notAfter)}
      </Field>
      <Field label="公钥">{alg}{ks}</Field>
      <Field label="签名算法">{c.signatureAlgorithm.name}</Field>
      <Field label="SHA-256"><code className="mono">{c.fingerprints.sha256}</code></Field>
      {c.extensions.subjectAltNames.length > 0 && (
        <Field label="SAN">
          <span className="tag-wrap">
            {c.extensions.subjectAltNames.map((n, i) => (
              <span key={i} className="tag">
                {n.kind}: {n.value}
              </span>
            ))}
          </span>
        </Field>
      )}
      {status?.diagnostics.map((d, i) => (
        <Diag key={i} d={d} />
      ))}
    </div>
  );
}

function KeyCard({ k, label }: { k: PrivateKeyInfo; label: string }) {
  return (
    <div className="card">
      <div className="card-head">
        <span className="kind kind-key">{label}</span>
        {k.encrypted && <Badge tone="warn">已加密</Badge>}
      </div>
      <Field label="格式">{k.format}</Field>
      <Field label="算法">{k.algorithm.name}</Field>
      <Field label="密钥长度">
        {k.keySizeBits ? `${k.keySizeBits} bit` : "—"}
        {k.curve ? ` · ${k.curve}` : ""}
      </Field>
      <Field label="DER 长度">{k.derLen} bytes</Field>
    </div>
  );
}

function PubKeyCard({ k }: { k: PublicKeyInfo }) {
  return (
    <div className="card">
      <div className="card-head">
        <span className="kind kind-pub">PUBLIC KEY</span>
      </div>
      <Field label="算法">
        {k.algorithm.name}
        {k.curve ? ` · ${k.curve}` : ""}
      </Field>
      <Field label="密钥长度">{k.keySizeBits ? `${k.keySizeBits} bit` : "—"}</Field>
      <Field label="SPKI SHA-256"><code className="mono">{k.spkiSha256}</code></Field>
    </div>
  );
}

function UnsupportedCard({ u }: { u: { label: string | null; derLen: number } }) {
  return (
    <div className="card">
      <div className="card-head">
        <span className="kind kind-unk">UNSUPPORTED</span>
      </div>
      <Field label="标签">{u.label ?? "(无)"}</Field>
      <Field label="DER 长度">{u.derLen} bytes</Field>
    </div>
  );
}

function ChainCard({ ch, index }: { ch: ChainSummary; index: number }) {
  return (
    <div className="chain">
      <span className="chain-i">链 #{index + 1}</span>
      {ch.complete ? <Badge tone="ok">完整</Badge> : <Badge tone="bad">不完整</Badge>}
      {ch.selfSignedOnly && <Badge tone="warn">仅自签名</Badge>}
      <span className="chain-idx">对象索引 {ch.indices.join(" → ")}</span>
      {ch.diagnostics.map((d, i) => (
        <Diag key={i} d={d} />
      ))}
    </div>
  );
}

function ItemCard({ item, status }: { item: BundleItem; status?: CertificateStatus }) {
  switch (item.kind) {
    case "certificate":
      return <CertCard c={item} status={status} />;
    case "privateKey":
      return <KeyCard k={item} label="PRIVATE KEY" />;
    case "publicKey":
      return <PubKeyCard k={item} />;
    case "unsupported":
      return <UnsupportedCard u={item} />;
    default:
      return null;
  }
}

export function CertViewer({ report }: { report: Report }) {
  const statusByIndex = new Map<number, CertificateStatus>();
  for (const s of report.certificates) statusByIndex.set(s.index, s);

  return (
    <div className="viewer">
      <div className="viewer-head">
        <span>来源格式 <b>{report.bundle.sourceFormat}</b></span>
        <span>评估时间 {fmtDate(report.evaluatedAt)}</span>
        <span>对象数 {report.bundle.items.length}</span>
      </div>
      {report.bundle.items.map((item, i) => (
        <ItemCard key={i} item={item} status={statusByIndex.get(i)} />
      ))}
      {report.bundle.chains.map((ch, i) => (
        <ChainCard key={`c${i}`} ch={ch} index={i} />
      ))}
      {report.bundle.diagnostics.map((d, i) => (
        <Diag key={`d${i}`} d={d} />
      ))}
    </div>
  );
}
