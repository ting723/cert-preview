mod utils;
mod x509;

use utils::{to_der, to_pem};
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

#[wasm_bindgen]
pub fn pem_to_der(pem_str: &str) -> Box<[u8]> {
    let rs = to_der(pem_str);
    match rs {
        Ok(data) => data.into_boxed_slice(),
        Err(_) => Box::new([]),
    }
}

#[wasm_bindgen]
pub fn der_to_pem(der_data: Vec<u8>) -> String {
    let rs = to_pem(der_data);
    match rs {
        Ok(pem) => pem,
        Err(_) => "".to_string(),
    }
}
