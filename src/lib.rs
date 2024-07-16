mod utils;
mod x509;

use wasm_bindgen::prelude::*;
use x509::CertInfo;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn get_cert_info(pem_str: &str) -> String {
    let cert_rs = CertInfo::from_pem(pem_str);
    match cert_rs {
        Ok(c) => serde_json::to_string(&c).unwrap_or("".to_string()),
        Err(_) => "".to_string(),
    }
}
