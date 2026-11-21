#!/usr/bin/env bash
# Generates the webhook serving certificate and the CA bundle the API server
# uses to verify it. This is a bootstrap helper for local clusters; production
# clusters should use cert-manager or the platform PKI.
set -euo pipefail

NAMESPACE="${NAMESPACE:-admission-guard}"
SERVICE="${SERVICE:-admission-guard}"
OUT_DIR="${OUT_DIR:-./deploy/generated}"
DAYS="${DAYS:-825}"

mkdir -p "$OUT_DIR"

# CA
openssl genrsa -out "$OUT_DIR/ca.key" 4096 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$OUT_DIR/ca.key" -sha256 -days "$DAYS" \
  -subj "/CN=admission-guard-ca" -out "$OUT_DIR/ca.crt"

# Serving cert with the SANs the API server dials.
cat > "$OUT_DIR/csr.conf" <<CONF
[req]
req_extensions = v3_req
distinguished_name = dn
prompt = no
[dn]
CN = ${SERVICE}.${NAMESPACE}.svc
[v3_req]
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SERVICE}
DNS.2 = ${SERVICE}.${NAMESPACE}
DNS.3 = ${SERVICE}.${NAMESPACE}.svc
DNS.4 = ${SERVICE}.${NAMESPACE}.svc.cluster.local
CONF

openssl genrsa -out "$OUT_DIR/tls.key" 2048 >/dev/null 2>&1
openssl req -new -key "$OUT_DIR/tls.key" -out "$OUT_DIR/tls.csr" -config "$OUT_DIR/csr.conf"
openssl x509 -req -in "$OUT_DIR/tls.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
  -CAcreateserial -out "$OUT_DIR/tls.crt" -days "$DAYS" -sha256 \
  -extensions v3_req -extfile "$OUT_DIR/csr.conf"

cat > "$OUT_DIR/apply.sh" <<APPLY
#!/usr/bin/env bash
# Applies the generated TLS material and the split webhook configuration.
set -euo pipefail
kubectl -n ${NAMESPACE} create secret tls admission-guard-tls \\
  --cert="$OUT_DIR/tls.crt" --key="$OUT_DIR/tls.key" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f <(admissionctl render-webhook-config \\
  --service ${SERVICE} --namespace ${NAMESPACE} --ca-bundle "$OUT_DIR/ca.crt")
APPLY
chmod +x "$OUT_DIR/apply.sh"

echo "wrote certificates to $OUT_DIR"
echo "next: ./$OUT_DIR/apply.sh (after building/admissionctl render-webhook-config)"
