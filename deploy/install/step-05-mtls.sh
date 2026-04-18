#!/usr/bin/env bash
# step-05-mtls.sh — Client mTLS material for edges. Hubs handle their own
# CA in install-hub.sh; this step is a no-op for hubs.
#
# Generates an ECDSA P-256 keypair and a CSR whose:
#   CN                 = GW_NODE_ID
#   URI SAN (node-id)  = gateway:node-id:<GW_NODE_ID>
#   URI SAN (node-type)= gateway:node-type:<GW_NODE_TYPE>
# matching internal/hub/mtls.go (SignCSR invariants).
#
# If the hub is reachable (step-03 set GW_HUB_REACHABLE=1), we submit the
# CSR to /v1/nodes/register and save the signed cert + CA bundle into
# staging. Otherwise we leave the CSR in staging and tell the operator to
# submit it manually.
#
# Bash >= 4.
set -euo pipefail

# shellcheck disable=SC1091
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

step_banner "Step 5/7  mTLS identity"

if [[ "${GW_NODE_TYPE:-}" == "hub" ]]; then
    log "Skipping mTLS client setup (hub creates its own CA)."
    exit 0
fi

have openssl || die "openssl is required for mTLS CSR generation"
stage_init

key_path="${GW_STAGE_DIR}/etc/client.key"
csr_path="${GW_STAGE_DIR}/etc/client.csr"
crt_path="${GW_STAGE_DIR}/etc/client.crt"
ca_path="${GW_STAGE_DIR}/etc/hub-ca.pem"

mkdir -p "$(dirname -- "$key_path")"

# ---------------------------------------------------------------------------
# Build an openssl config that includes the two URI SANs the hub expects.
# We write it as a temp file so openssl can read it; the file itself has
# no secret content.
# ---------------------------------------------------------------------------
cnf="${GW_STAGE_DIR}/csr.cnf"
cat > "$cnf" <<CNF
[req]
prompt = no
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = ${GW_NODE_ID}

[req_ext]
subjectAltName = @alt_names

[alt_names]
URI.1 = gateway:node-id:${GW_NODE_ID}
URI.2 = gateway:node-type:${GW_NODE_TYPE}
CNF

# ECDSA P-256 private key.
openssl ecparam -name prime256v1 -genkey -noout -out "$key_path" 2>/dev/null \
    || die "openssl ecparam failed"
chmod_secret "$key_path"

# CSR.
openssl req -new -key "$key_path" -out "$csr_path" \
    -config "$cnf" -reqexts req_ext 2>/dev/null \
    || die "openssl req -new failed"
chmod 644 "$csr_path"

log "Generated ECDSA P-256 key + CSR for node_id=${GW_NODE_ID}"

# ---------------------------------------------------------------------------
# Submit CSR to hub if reachable.
# ---------------------------------------------------------------------------
if [[ "${GW_HUB_REACHABLE:-0}" == "1" ]] && have curl && [[ -n "${GW_HUB_ADDR:-}" ]]; then
    info "Submitting CSR to hub at ${GW_HUB_ADDR}..."
    csr_pem="$(cat -- "$csr_path")"
    # Build a small JSON payload without jq.
    payload=$(cat <<JSON
{"node_id":"${GW_NODE_ID}","node_type":"${GW_NODE_TYPE}","csr_pem":$(printf '%s' "$csr_pem" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '"%s"' "$(printf '%s' "$csr_pem" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g')")}
JSON
)
    resp_file="${GW_STAGE_DIR}/register_resp.json"
    http_code="$(curl --silent --show-error --max-time 10 \
        --output "$resp_file" --write-out '%{http_code}' \
        -H 'Content-Type: application/json' \
        --data "$payload" \
        "http://${GW_HUB_ADDR}/v1/nodes/register" 2>/dev/null || echo "000")"

    if [[ "$http_code" == "200" ]] && [[ -s "$resp_file" ]]; then
        # Response is expected to contain cert_pem and ca_pem fields.
        # Parse minimally without jq.
        if have python3; then
            python3 - "$resp_file" "$crt_path" "$ca_path" <<'PY' || die "failed to parse register response"
import json, sys
path, crt_path, ca_path = sys.argv[1:4]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
for key, target in (("cert_pem", crt_path), ("ca_pem", ca_path)):
    v = data.get(key, "")
    if not v:
        raise SystemExit(f"missing field in hub response: {key}")
    with open(target, "w", encoding="utf-8") as out:
        out.write(v)
PY
            chmod 600 "$crt_path"
            chmod 644 "$ca_path"
            log "CSR signed by hub — cert + CA saved to staging."
        else
            warn "python3 not available — cannot parse hub response automatically."
            warn "Raw response kept at $resp_file; extract cert manually."
        fi
    else
        warn "Hub registration returned HTTP $http_code — will leave CSR staged."
        warn "Submit it manually: cat /etc/gateway/client.csr | curl ... /v1/nodes/register"
    fi
else
    info "Hub not reachable or curl unavailable — leaving CSR in staging."
    info "Submit it manually once the hub is up and place the signed cert at"
    info "  /etc/gateway/client.crt"
    info "and the CA bundle at"
    info "  /etc/gateway/hub-ca.pem"
fi

log "Step 5 complete."
