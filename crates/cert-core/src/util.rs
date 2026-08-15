//! Dependency-free helpers shared across layers.

/// Lower-case hex, no separator.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Lower-case hex with `:` between octets — the conventional rendering for
/// serial numbers and fingerprints.
pub fn hex_colon(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(bytes.len() * 3 - 1);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Format a Unix timestamp as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Implemented locally rather than pulling in `chrono` or enabling `time`'s
/// formatting features: this is ~30 lines of integer arithmetic against
/// several hundred KB of dependency, and WASM size is a stated constraint.
///
/// Uses Howard Hinnant's `civil_from_days` algorithm, valid across the whole
/// range of dates any X.509 certificate can express.
pub fn format_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs_of_day = ts.rem_euclid(86_400);

    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days since 1970-01-01 -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Human friendly duration, e.g. `342 days`, `3 hours`, `expired 12 days ago`.
pub fn humanize_seconds(secs: i64) -> String {
    let a = secs.abs();
    let (n, unit) = if a >= 86_400 {
        (a / 86_400, "day")
    } else if a >= 3_600 {
        (a / 3_600, "hour")
    } else if a >= 60 {
        (a / 60, "minute")
    } else {
        (a, "second")
    };
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} {unit}{plural}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_rendering() {
        assert_eq!(hex(&[0x0a, 0xff]), "0aff");
        assert_eq!(hex_colon(&[0x0a, 0xff, 0x00]), "0a:ff:00");
        assert_eq!(hex_colon(&[]), "");
    }

    #[test]
    fn utc_matches_known_timestamps() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        // The not_before of the Google cert used in the original README.
        assert_eq!(format_utc(1_719_214_954), "2024-06-24T07:42:34Z");
        assert_eq!(format_utc(1_726_472_553), "2024-09-16T07:42:33Z");
        // Leap day.
        assert_eq!(format_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        // Pre-epoch, exercising the Euclidean division path.
        assert_eq!(format_utc(-1), "1969-12-31T23:59:59Z");
        // The RFC 5280 "no well-defined expiry" sentinel.
        assert_eq!(format_utc(253_402_300_799), "9999-12-31T23:59:59Z");
    }

    #[test]
    fn duration_rendering() {
        assert_eq!(humanize_seconds(86_400), "1 day");
        assert_eq!(humanize_seconds(-172_800), "2 days");
        assert_eq!(humanize_seconds(59), "59 seconds");
        assert_eq!(humanize_seconds(3_600), "1 hour");
    }
}
