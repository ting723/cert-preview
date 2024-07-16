//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use cert_preview::get_cert_info;
use wasm_bindgen_test::{console_log, *};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    assert_eq!(1 + 1, 2);
    let cert_info_json = get_cert_info(
        r"-----BEGIN CERTIFICATE-----
MIIEVTCCAz2gAwIBAgIQKCrdQRgWxxQKos8VCqLgLTANBgkqhkiG9w0BAQsFADA7
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMQww
CgYDVQQDEwNXUjIwHhcNMjQwNjI0MDc0MjM0WhcNMjQwOTE2MDc0MjMzWjAZMRcw
FQYDVQQDEw53d3cuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BMn2mdVJyscwlrNxZPhX798s8yNdMisZUaLHerD3c7nUmTV0N0cbJsjUJYWGME5R
EnXaQD8FsWhAZ/Ev0uKS1oKjggJAMIICPDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUiGHTRG3nSDSU
taLazcM2QgZjUTkwHwYDVR0jBBgwFoAU3hse7XkV1D43JMMhu+w0OW1CsjAwWAYI
KwYBBQUHAQEETDBKMCEGCCsGAQUFBzABhhVodHRwOi8vby5wa2kuZ29vZy93cjIw
JQYIKwYBBQUHMAKGGWh0dHA6Ly9pLnBraS5nb29nL3dyMi5jcnQwGQYDVR0RBBIw
EIIOd3d3Lmdvb2dsZS5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwNgYDVR0fBC8w
LTAroCmgJ4YlaHR0cDovL2MucGtpLmdvb2cvd3IyL29CRllZYWh6Z1ZJLmNybDCC
AQMGCisGAQQB1nkCBAIEgfQEgfEA7wB2AO7N0GTV2xrOxVy3nbTNE6Iyh0Z8vOze
w1FIWUZxH7WbAAABkElpSoQAAAQDAEcwRQIhAPi9V6iNZ4737dsloo4yu0QWl/9p
OnwELs+NFNitJQTdAiA6VQn72T4xLgq8Il4AP0NEdm2WsXQW1U92S6p8dsgwdgB1
AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRzAAABkElpSqoAAAQDAEYw
RAIgQt/dcMehgMdyWmRsDB6xRMp0HrTzXCaksJrmiR2kM8ACIBWwoe5GNhqiD20G
Yyfx69/k9MDanhzJ/v5XZszZNfuKMA0GCSqGSIb3DQEBCwUAA4IBAQB3/2ybZwY3
jFI9RwSydvE1oSJQcjM/6LueYYvAJRuXyxag6OdNRHafcx5SLbG1U/8nP1qIyJYq
BcnSWJ6y1YGUmniYQr6lSd7I6NqyHQ681k7uiPHkj6ZRWCrt0Nj1x+n3Ir+Lr8hA
2qYAF10Aw0Elo6oco/iMkibhudp5DIKTkfxqBf98bmVR/DJAHndgb/ON8ajOIDbQ
p368KcZWrQLn6O6t5SJ+PhuPsG4HJX/kA3zgh9S6PoOiaApOneqTiPm3CKinzK/K
x3E4ajtH71dHOaPQ+divw7ly1KbW7aslHG0HA0faFOH7NC1g3RgUejY1CfVI4F0F
7RWeA0IhCxEI
-----END CERTIFICATE-----
",
    );
    console_log!("{}", cert_info_json);
}
