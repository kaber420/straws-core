#!/bash
set -e

# Directory for certs
mkdir -p certs
cd certs

echo "Generating CA..."
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.crt -subj "/C=MX/ST=CDMX/L=CDMX/O=StrawsLite/CN=StrawsLite Test CA"

echo "Generating certificate for careldpos..."
openssl genrsa -out careldpos.key 2048
openssl req -new -key careldpos.key -out careldpos.csr -subj "/C=MX/ST=CDMX/L=CDMX/O=StrawsLite/CN=careldpos"

# Extension for SAN
cat > careldpos.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = careldpos
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in careldpos.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out careldpos.crt -days 500 -sha256 -extfile careldpos.ext

echo "Certificates generated in go-engine/certs/"
