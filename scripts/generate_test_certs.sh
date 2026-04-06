#!/bin/bash

# Configuration
DOMAIN="mysite.test"
CERTS_DIR="/home/kaber420/Documentos/proyectos/strawslite-firefox/go-engine/certs"
mkdir -p "$CERTS_DIR"

echo "Generating CA..."
openssl genrsa -out "$CERTS_DIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$CERTS_DIR/ca.key" -sha256 -days 365 -out "$CERTS_DIR/ca.crt" -subj "/C=US/ST=State/L=City/O=Straws/CN=StrawsLocalCA"

echo "Generating Server Key..."
openssl genrsa -out "$CERTS_DIR/$DOMAIN.key" 2048

echo "Generating CSR..."
openssl req -new -key "$CERTS_DIR/$DOMAIN.key" -out "$CERTS_DIR/$DOMAIN.csr" -subj "/C=US/ST=State/L=City/O=Straws/CN=$DOMAIN"

echo "Signing Certificate..."
cat > "$CERTS_DIR/$DOMAIN.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = *.$DOMAIN
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in "$CERTS_DIR/$DOMAIN.csr" -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/$DOMAIN.crt" -days 365 -sha256 -extfile "$CERTS_DIR/$DOMAIN.ext"

echo "Certs generated for $DOMAIN in $CERTS_DIR"
ls -l "$CERTS_DIR"
