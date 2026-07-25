#!/usr/bin/env bash
# Regenerate the RFC 3161 test fixtures.
#
# Requires openssl. Run from this directory:  ./regenerate.sh
#
# The committed fixtures are the .tsr tokens, the .crt certificates and the
# timestamped data — everything needed to *verify*. Private keys are generated
# here and deleted at the end: the test suite only ever verifies signatures, so
# it never needs the keys, and a repository that argues for careful handling of
# evidence should not casually ship signing keys.
set -euo pipefail

rm -f ./*.key ./*.csr ./*.srl index.txt* serial* tsa_serial ec_serial rogue_serial

echo "01" > tsa_serial; echo "01" > ec_serial; echo "01" > rogue_serial
echo "01" > serial; : > index.txt

# Test CA and a signer carrying the timeStamping EKU.
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 \
  -subj "/CN=Beweiskette Test TSA CA/O=Beweiskette Test Fixtures" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout tsa.key -out tsa.csr \
  -subj "/CN=Beweiskette Test TSA/O=Beweiskette Test Fixtures" 2>/dev/null
openssl x509 -req -in tsa.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tsa.crt \
  -days 3650 -extfile openssl-tsa.cnf -extensions tsa_cert_ext 2>/dev/null

printf 'beweiskette-test-chain-head' > head.txt
printf 'some other document entirely' > other.txt

openssl ts -query -data head.txt -sha256 -cert -out request.tsq 2>/dev/null
openssl ts -reply -queryfile request.tsq -config openssl-tsa.cnf -out response.tsr 2>/dev/null

# A valid token over unrelated data.
openssl ts -query -data other.txt -sha256 -cert -out request-other.tsq 2>/dev/null
openssl ts -reply -queryfile request-other.tsq -config openssl-tsa.cnf -out response-other.tsr 2>/dev/null

# A genuine token from a TSA we do not pin.
openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue-ca.key -out rogue-ca.crt -days 3650 \
  -subj "/CN=Rogue Test TSA CA/O=Beweiskette Test Fixtures" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout rogue-tsa.key -out rogue-tsa.csr \
  -subj "/CN=Rogue Test TSA/O=Beweiskette Test Fixtures" 2>/dev/null
openssl x509 -req -in rogue-tsa.csr -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial \
  -out rogue-tsa.crt -days 3650 -extfile openssl-tsa.cnf -extensions tsa_cert_ext 2>/dev/null
sed -e 's/^signer_cert  *= tsa.crt/signer_cert = rogue-tsa.crt/' \
    -e 's/^signer_key  *= tsa.key/signer_key = rogue-tsa.key/' \
    -e 's/^certs  *= ca.crt/certs = rogue-ca.crt/' \
    -e 's/^serial  *= tsa_serial/serial = rogue_serial/' openssl-tsa.cnf > openssl-rogue.cnf
openssl ts -reply -queryfile request.tsq -config openssl-rogue.cnf -out response-rogue.tsr 2>/dev/null

# An ECDSA signer, to prove the verifier is not RSA-only.
openssl ecparam -name prime256v1 -genkey -noout -out ec-tsa.key 2>/dev/null
openssl req -new -key ec-tsa.key -out ec-tsa.csr \
  -subj "/CN=Beweiskette EC Test TSA/O=Beweiskette Test Fixtures" 2>/dev/null
openssl x509 -req -in ec-tsa.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out ec-tsa.crt \
  -days 3650 -extfile openssl-tsa.cnf -extensions tsa_cert_ext 2>/dev/null
sed -e 's/^signer_cert  *= tsa.crt/signer_cert = ec-tsa.crt/' \
    -e 's/^signer_key  *= tsa.key/signer_key = ec-tsa.key/' \
    -e 's/^serial  *= tsa_serial/serial = ec_serial/' openssl-tsa.cnf > openssl-ec.cnf
openssl ts -reply -queryfile request.tsq -config openssl-ec.cnf -out response-ec.tsr 2>/dev/null

echo "--- independent verification ---"
openssl ts -verify -in response.tsr    -data head.txt -CAfile ca.crt       -untrusted tsa.crt       2>&1 | tail -1
openssl ts -verify -in response-ec.tsr -data head.txt -CAfile ca.crt       -untrusted ec-tsa.crt    2>&1 | tail -1
openssl ts -verify -in response-rogue.tsr -data head.txt -CAfile rogue-ca.crt -untrusted rogue-tsa.crt 2>&1 | tail -1

# Keys are deliberately not kept.
rm -f ./*.key ./*.csr ./*.srl index.txt* serial tsa_serial ec_serial rogue_serial
echo "done — private keys discarded"
