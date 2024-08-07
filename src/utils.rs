use anyhow::Error;
use base64::{engine::general_purpose, Engine};
use regex::Regex;

const PEM_HEADER_REG: &str = "-----BEGIN.*-----";
const PEM_TAIL_REG: &str = "-----END.*----";

#[allow(dead_code)]
pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
pub fn pem_to_base64(pem: &str) -> Result<String, Error> {
    let header_reg = Regex::new(PEM_HEADER_REG)?;
    let tail_reg = Regex::new(PEM_TAIL_REG)?;
    let binding = header_reg.replace_all(pem, "");
    let trim_str = tail_reg.replace_all(&binding, "");
    let pem_base64 = trim_str
        .replace(" ", "")
        .replace("\n", "")
        .replace("\t", "");
    Ok(pem_base64)
}

pub fn to_der(pem_str: &str) -> Result<Vec<u8>, Error> {
    let pem_str = pem_to_base64(pem_str)?;
    let mut buffer = Vec::<u8>::new();
    general_purpose::STANDARD.decode_vec(pem_str, &mut buffer)?;
    return Ok(buffer);
}

pub fn to_pem(der_data: Vec<u8>) -> Result<String, Error> {
    let base64_cert = general_purpose::STANDARD.encode(der_data);
    let mut tmp = String::new();
    for i in 0..base64_cert.len() {
        if (i + 1) % 64 == 0 {
            tmp.push_str(&base64_cert[i - 63..i + 1]);
            tmp.push_str("\n")
        }
        let r = base64_cert.len() % 64;
        if r % 64 != 0 && i == base64_cert.len() - 1 {
            tmp.push_str(&base64_cert[i - r % 64 + 1..i + 1]);
            tmp.push_str("\n")
        }
    }
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}-----END CERTIFICATE-----\n",
        tmp
    );
    Ok(pem)
}
