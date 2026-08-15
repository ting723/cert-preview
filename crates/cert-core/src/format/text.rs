//! Human-readable text rendering of a [`Report`].
//!
//! Intended for `STDOUT` in the CLI and for quick inspection. Compact enough
//! for a terminal, complete enough to show every field a viewer cares about.

use crate::model::{BundleItem, CertificateInfo, Report};

/// Render `report` as multi-paragraph text, one block per object.
pub fn text(report: &Report) -> String {
    let mut out = String::new();

    render_chains(report, &mut out);

    let mut first = report.certificates.is_empty();
    for status in &report.certificates {
        if !first {
            out.push('\n');
        }
        first = false;

        let Some(BundleItem::Certificate(cert)) = report.bundle.get(status.index as usize) else {
            continue;
        };
        render_certificate(cert, status, &mut out);
    }

    // Surface any non-certificate items (keys, unsupported) briefly.
    for (idx, item) in report.bundle.items.iter().enumerate() {
        match item {
            BundleItem::PrivateKey(k) => {
                out.push('\n');
                out.push_str(&format!(
                    "=== Private key ({idx}) · {} ===\n",
                    k.format.as_str()
                ));
                out.push_str(&format!("  Algorithm : {}\n", k.algorithm.name));
                if let Some(bits) = k.key_size_bits {
                    out.push_str(&format!("  Size      : {bits} bit\n"));
                }
                if k.encrypted {
                    out.push_str("  Encrypted : yes\n");
                }
            }
            BundleItem::PublicKey(k) => {
                out.push('\n');
                out.push_str(&format!("=== Public key ({idx}) ===\n"));
                out.push_str(&format!("  Algorithm : {}\n", k.algorithm.name));
                if let Some(bits) = k.key_size_bits {
                    out.push_str(&format!("  Size      : {bits} bit\n"));
                }
                out.push_str(&format!("  SPKI SHA-256: {}\n", k.spki_sha256));
            }
            BundleItem::Unsupported(u) => {
                out.push('\n');
                out.push_str(&format!(
                    "=== Unsupported ({idx}) · {:?} ===\n",
                    u.label
                ));
                out.push_str(&format!("  Reason    : {}\n", u.reason));
            }
            BundleItem::Certificate(_) => {}
        }
    }

    if out.is_empty() {
        out.push_str("(no objects found)\n");
    }
    out
}

fn render_chains(report: &Report, out: &mut String) {
    if report.bundle.chains.is_empty() {
        return;
    }
    out.push_str("=== Chains ===\n");
    for chain in report.bundle.chains.iter() {
        let mut line = String::from("  ");
        for (k, idx) in chain.indices.iter().enumerate() {
            if k > 0 {
                line.push_str(" -> ");
            }
            let label = report
                .bundle
                .get(*idx as usize)
                .and_then(|i| i.as_certificate())
                .map(|c| c.subject.label().to_string())
                .unwrap_or_else(|| format!("item{idx}"));
            line.push_str(&label);
        }
        let tag = if chain.complete {
            "complete"
        } else {
            "INCOMPLETE"
        };
        line.push_str(&format!("   [{tag}]\n"));
        for d in &chain.diagnostics {
            line.push_str(&format!("    - {} {}\n", d.level.as_str().to_uppercase(), d.message));
        }
        out.push_str(&line);
    }
    out.push('\n');
}

fn render_certificate(cert: &CertificateInfo, status: &crate::model::CertificateStatus, out: &mut String) {
    out.push_str(&format!(
        "=== Certificate {} · {} ===\n",
        status.index,
        cert.label()
    ));
    let kv = |out: &mut String, k: &str, v: &str| {
        out.push_str(&format!("  {:<10}: {v}\n", k));
    };

    kv(out, "Subject", &cert.subject.rfc4514);
    kv(out, "Issuer", &cert.issuer.rfc4514);
    kv(out, "Version", &cert.version.to_string());
    kv(out, "Serial", &cert.serial_number);
    kv(
        out,
        "Validity",
        &format!(
            "{} .. {}",
            cert.validity.not_before_utc, cert.validity.not_after_utc
        ),
    );
    kv(out, "Status", &status.validity.summary());
    kv(out, "PublicKey", &cert.public_key.summary());
    kv(out, "Signature", &cert.signature_algorithm.name);
    kv(out, "SelfSigned", if cert.self_issued { "yes" } else { "no" });

    if !cert.extensions.subject_alt_names.is_empty() {
        let san = cert
            .extensions
            .subject_alt_names
            .iter()
            .map(|n| match n.kind.as_str() {
                "dns" => format!("DNS:{}", n.value),
                "ip" => format!("IP:{}", n.value),
                "email" => format!("email:{}", n.value),
                "uri" => format!("URI:{}", n.value),
                other => format!("{other}:{}", n.value),
            })
            .collect::<Vec<_>>()
            .join(", ");
        kv(out, "SAN", &san);
    }
    if !cert.extensions.key_usage.is_empty() {
        kv(out, "KeyUsage", &cert.extensions.key_usage.join(", "));
    }
    if !cert.extensions.extended_key_usage.is_empty() {
        kv(out, "ExtKeyUse", &cert.extensions.extended_key_usage.join(", "));
    }
    if let Some(bc) = &cert.extensions.basic_constraints {
        kv(
            out,
            "BasicCons",
            &if let Some(p) = bc.path_len_constraint {
                format!("CA:{}, pathlen:{}", bc.ca, p)
            } else {
                format!("CA:{}", bc.ca)
            },
        );
    }
    if let Some(host) = &status.hostname {
        kv(out, "Hostname", &host.summary());
    }
    if !status.diagnostics.is_empty() {
        for d in &status.diagnostics {
            kv(
                out,
                "Note",
                &format!("{} [{}]", d.message, d.code),
            );
        }
    }
    if !cert.extensions.certificate_policies.is_empty() {
        kv(out, "Policies", &cert.extensions.certificate_policies.join(", "));
    }
}
