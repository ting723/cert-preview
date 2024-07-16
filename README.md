<div align="center">

  <h1><code>Certificate Preview Lib</code></h1>

<strong>用于展示基本的证书信息</strong>

</div>

## 用法

```ts
import { get_cert_info } from "cert-preview";
let cert = `-----BEGIN CERTIFICATE-----
MIIEVTCCAz2gAwIBAgIQKCrdQRgWxxQKos8VCqLgLTANBgkqhkiG9w0BAQsFADA7
p368KcZWrQLn6O6t5SJ+PhuPsG4HJX/kA3zgh9S6PoOiaApOneqTiPm3CKinzK/K
......
x3E4ajtH71dHOaPQ+divw7ly1KbW7aslHG0HA0faFOH7NC1g3RgUejY1CfVI4F0F
7RWeA0IhCxEI
-----END CERTIFICATE-----`;
let cert_json = get_cert_info(cert);
```

> 其中返回结果 cert_json 的信息为:

```json
{
  // 证书序列号
  "serial_number": "28:2a:dd:41:18:16:c7:14:0a:a2:cf:15:0a:a2:e0:2d",
  "subject": {
    // 主题
    "common_name": "www.google.com",
    "country": "",
    "organization": "",
    "locality": "",
    "organizational_unit": "",
    "state": ""
  },
  "issuer": {
    // 签发者信息
    "common_name": "WR2",
    "country": "US",
    "organization": "Google Trust Services",
    "locality": "",
    "organizational_unit": "",
    "state": ""
  },
  // 有效期
  "not_before": 1719214954, // Unix时间窗
  "not_after": 1726472553
}
```

## 注意项
- 使用Rust语言开发,其中采用的wasm-pack工具进行的打包,命令如下
```sh
wasm-pack build --release --target web
```
> 详情见: https://rustwasm.github.io/docs/wasm-bindgen/reference/deployment.html#bundlers
- 上述命令打出的包，在不使用ES模块的web中，可能无法运行
