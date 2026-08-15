#!/usr/bin/env bash
# Regenerate the shared test vectors.
#
# The output is committed, so this script is only run when a new case is
# needed. Validity windows are pinned with -not_before/-not_after (OpenSSL
# 3.5+) so that regenerating produces certificates with identical dates and
# the snapshots stay comparable.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p certs keys
cd certs

NB=20240101000000Z
NA=20340101000000Z

subj() { printf '/C=GB/ST=Greater London/L=London/O=Example Ltd/CN=%s' "$1"; }

# --- RSA leaf, self-signed, with a rich SAN set -----------------------------
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout ../keys/rsa-2048.key.pem -out rsa-leaf.pem \
  -subj "$(subj example.com)" \
  -not_before "$NB" -not_after "$NA" \
  -addext "subjectAltName=DNS:example.com,DNS:*.example.com,IP:192.0.2.10,IP:2001:db8::1,email:admin@example.com,URI:https://example.com/" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "certificatePolicies=2.23.140.1.2.1" \
  -addext "authorityInfoAccess=OCSP;URI:http://ocsp.example.com,caIssuers;URI:http://ca.example.com/ca.crt" \
  -addext "crlDistributionPoints=URI:http://crl.example.com/ca.crl" 2>/dev/null

# --- EC leaf ----------------------------------------------------------------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes \
  -keyout ../keys/ec-p256.key.pem -out ec-leaf.pem \
  -subj "$(subj ec.example.com)" \
  -not_before "$NB" -not_after "$NA" \
  -addext "subjectAltName=DNS:ec.example.com" \
  -addext "basicConstraints=critical,CA:FALSE" 2>/dev/null

# --- A three certificate chain: root -> intermediate -> leaf ----------------
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout root.key.pem -out root.pem \
  -subj "/C=GB/O=Example Trust/CN=Example Root CA" \
  -not_before "$NB" -not_after "$NA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -new -newkey rsa:2048 -sha256 -nodes \
  -keyout inter.key.pem -out inter.csr \
  -subj "/C=GB/O=Example Trust/CN=Example Issuing CA" 2>/dev/null
openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key.pem -sha256 \
  -set_serial 0x1001 -not_before "$NB" -not_after "$NA" \
  -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n') \
  -out inter.pem 2>/dev/null

openssl req -new -newkey rsa:2048 -sha256 -nodes \
  -keyout leaf.key.pem -out leaf.csr \
  -subj "/C=GB/O=Example Ltd/CN=www.example.org" 2>/dev/null
openssl x509 -req -in leaf.csr -CA inter.pem -CAkey inter.key.pem -sha256 \
  -set_serial 0x2002 -not_before "$NB" -not_after 20250101000000Z \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:www.example.org,DNS:example.org\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n') \
  -out leaf.pem 2>/dev/null

cat leaf.pem inter.pem root.pem > chain.pem
# Same chain, shuffled, to prove ordering is reconstructed not assumed.
cat root.pem leaf.pem inter.pem > chain-shuffled.pem
# Leaf only: an incomplete chain.
cp leaf.pem chain-incomplete.pem

openssl x509 -in rsa-leaf.pem -outform der -out rsa-leaf.der
openssl x509 -in leaf.pem -outform der -out leaf.der

rm -f inter.csr leaf.csr

# --- Keys -------------------------------------------------------------------
cd ../keys
openssl pkey -in rsa-2048.key.pem -out rsa-2048.pkcs8.pem
openssl pkey -in rsa-2048.key.pem -traditional -out rsa-2048.pkcs1.pem
openssl pkey -in rsa-2048.key.pem -pubout -out rsa-2048.spki.pem
openssl rsa -in rsa-2048.key.pem -RSAPublicKey_out -out rsa-2048.pkcs1-pub.pem 2>/dev/null

openssl pkey -in ec-p256.key.pem -out ec-p256.pkcs8.pem
openssl ec -in ec-p256.key.pem -out ec-p256.sec1.pem 2>/dev/null
openssl pkey -in ec-p256.key.pem -pubout -out ec-p256.spki.pem

openssl genpkey -algorithm ed25519 -out ed25519.pkcs8.pem 2>/dev/null
openssl pkey -in ed25519.pkcs8.pem -pubout -out ed25519.spki.pem

openssl pkcs8 -topk8 -in rsa-2048.pkcs8.pem -out rsa-2048.encrypted.pem \
  -v2 aes-256-cbc -passout pass:testpassword

rm -f rsa-2048.key.pem ec-p256.key.pem
cd ../certs && rm -f root.key.pem inter.key.pem leaf.key.pem

echo "fixtures regenerated"
