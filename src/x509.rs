use anyhow::{bail, Error};
use base64::{engine::general_purpose, Engine};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use x509_parser::{
    der_parser::Oid,
    oid_registry::{
        OID_X509_COMMON_NAME, OID_X509_COUNTRY_NAME, OID_X509_LOCALITY_NAME,
        OID_X509_ORGANIZATIONAL_UNIT, OID_X509_ORGANIZATION_NAME, OID_X509_STATE_OR_PROVINCE_NAME,
    },
    parse_x509_certificate,
};

const PEM_HEADER_REG: &str = "-----BEGIN.*-----";
const PEM_TAIL_REG: &str = "-----END.*----";

#[derive(Debug, Serialize, Deserialize)]
pub struct CertInfo {
    serial_number: String,
    subject: XName,
    issuer: XName,
    not_before: i64,
    not_after: i64,
}

impl CertInfo {
    fn new(pem_data: &[u8]) -> Result<Self, Error> {
        let cert_result = parse_x509_certificate(pem_data);
        match cert_result {
            Ok((_, cert)) => Ok(Self {
                serial_number: cert.tbs_certificate.raw_serial_as_string(),
                subject: XName::new(&cert.tbs_certificate.subject),
                issuer: XName::new(&cert.tbs_certificate.issuer),
                not_before: cert
                    .tbs_certificate
                    .validity
                    .not_before
                    .to_datetime()
                    .unix_timestamp(),
                not_after: cert
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_datetime()
                    .unix_timestamp(),
            }),
            Err(_) => bail!("new is error"),
        }
    }

    fn from_base64(pem_base64: &str) -> Result<Self, Error> {
        let mut buffer = Vec::<u8>::new();
        let rs = general_purpose::STANDARD.decode_vec(pem_base64, &mut buffer);
        match rs {
            Ok(_) => Self::new(&buffer),
            Err(_) => bail!("from_base64 is error"),
        }
    }

    pub fn from_pem(pem: &str) -> anyhow::Result<Self, Error> {
        let header_reg = Regex::new(PEM_HEADER_REG)?;
        let tail_reg = Regex::new(PEM_TAIL_REG).unwrap();
        let binding = header_reg.replace_all(pem, "");
        let trim_str = tail_reg.replace_all(&binding, "");
        let pem_base64 = trim_str
            .replace(" ", "")
            .replace("\n", "")
            .replace("\t", "");
        return Self::from_base64(&pem_base64);
    }
}

impl Display for CertInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Serial Number: {} \n Subject: {} \n Issuer:{}, \n Not Before: {}, \n Not After:{}",
            self.serial_number, self.subject, self.issuer, self.not_before, self.not_after
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct XName {
    common_name: String,
    country: String,
    organization: String,
    locality: String,
    organizational_unit: String,
    state: String,
}

impl Display for XName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CN={}, C={}, O={}, L={}, OU={}, ST={}",
            self.common_name,
            self.country,
            self.organization,
            self.locality,
            self.organizational_unit,
            self.state
        )
    }
}

impl XName {
    fn new(name: &x509_parser::x509::X509Name) -> Self {
        XName {
            common_name: Self::parse(name, OID_X509_COMMON_NAME),
            country: Self::parse(name, OID_X509_COUNTRY_NAME),
            organization: Self::parse(name, OID_X509_ORGANIZATION_NAME),
            locality: Self::parse(name, OID_X509_LOCALITY_NAME),
            organizational_unit: Self::parse(name, OID_X509_ORGANIZATIONAL_UNIT),
            state: Self::parse(name, OID_X509_STATE_OR_PROVINCE_NAME),
        }
    }

    fn parse(name: &x509_parser::x509::X509Name, oid: Oid<'static>) -> String {
        let s = name.iter_by_oid(&oid).next().and_then(|n| n.as_str().ok());
        match s {
            Some(n) => n.to_string(),
            None => "".to_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::x509::CertInfo;

    #[test]
    pub fn test() {
        use x509_parser::{certificate::X509Certificate, prelude::FromDer};

        static IGCA_DER: &[u8] = include_bytes!("../resource/1.der");

        let c = CertInfo::new(IGCA_DER);
        println!("Cert Info: {}", serde_json::to_string(&c.unwrap()).unwrap());
        let res = X509Certificate::from_der(IGCA_DER);
        match res {
            Ok((rem, cert)) => {
                assert!(rem.is_empty());
                println!("Cert Info: {}", cert.tbs_certificate.issuer.to_string());
            }
            _ => panic!("x509 parsing failed: {:?}", res),
        }
    }
}
