//! Compact aligned-table rendering of a [`Report`].
//!
//! One row per certificate, suitable for a terminal or a narrow panel. Cells
//! are truncated (with a trailing `…`) to keep the row width bounded.

use crate::model::{BundleItem, Report};

const WIDTHS: [usize; 6] = [3, 28, 24, 12, 14, 12];
const HEADERS: [&str; 6] = ["#", "SUBJECT", "ISSUER", "EXPIRES", "KEY", "STATUS"];

/// Render `report` as a fixed-width table.
pub fn table(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&rule());
    out.push_str(&header_row());
    out.push_str(&rule());

    for status in &report.certificates {
        let Some(BundleItem::Certificate(cert)) = report.bundle.get(status.index as usize) else {
            continue;
        };
        let expires = &cert.validity.not_after_utc[..10.min(cert.validity.not_after_utc.len())];
        let status_cell = match status.hostname.as_ref() {
            Some(h) if !h.matched => "host✗",
            _ => status.validity.state.as_str(),
        };
        let row = [
            status.index.to_string(),
            cert.subject.label().to_string(),
            cert.issuer.label().to_string(),
            expires.to_string(),
            cert.public_key.summary(),
            status_cell.to_string(),
        ];
        out.push_str(&cells(&row));
    }

    out.push_str(&rule());
    out
}

fn header_row() -> String {
    cells(&HEADERS.map(|s| s.to_string()))
}

fn cells(values: &[String]) -> String {
    let mut line = String::from("│");
    for (i, v) in values.iter().enumerate() {
        let w = WIDTHS[i];
        line.push(' ');
        if v.chars().count() > w {
            let truncated: String = v.chars().take(w.saturating_sub(1)).collect();
            line.push_str(&format!("{truncated}…"));
        } else {
            line.push_str(v);
            let pad = w - v.chars().count();
            line.push_str(&" ".repeat(pad));
        }
        line.push_str(" │");
    }
    line.push('\n');
    line
}

fn rule() -> String {
    let mut line = String::from("├");
    for w in WIDTHS {
        line.push_str(&"─".repeat(w + 2));
        line.push('┼');
    }
    // Replace the trailing ┼ with ┤ for a clean right border.
    line.pop();
    line.push('┤');
    line.push('\n');
    line
}
