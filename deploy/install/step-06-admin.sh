#!/usr/bin/env bash
# step-06-admin.sh — Generate the hidden admin slug + two tokens.
#
# Everything generated here is a secret. It is written to the staging
# directory under 0600 permissions and only revealed to the operator
# during the finalize step (step-07) between "SAVE THIS ONCE" markers.
#
# Outputs (env):
#   GW_ADMIN_SLUG, GW_ADMIN_TOKEN1, GW_ADMIN_TOKEN2
# Outputs (staged files):
#   <stage>/etc/admin.env   (mode 0600)
#
# Bash >= 4.
set -euo pipefail

# shellcheck disable=SC1091
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

step_banner "Step 6/7  Admin credentials"

stage_init

# slug is 16 bytes of hex (32 chars); each token is 32 bytes of hex (64 chars).
# These are distinct length choices so the three components are not
# accidentally-swappable by humans.
GW_ADMIN_SLUG="${GW_ADMIN_SLUG:-$(rand_hex 16)}"
GW_ADMIN_TOKEN1="${GW_ADMIN_TOKEN1:-$(rand_hex 32)}"
GW_ADMIN_TOKEN2="${GW_ADMIN_TOKEN2:-$(rand_hex 32)}"
export GW_ADMIN_SLUG GW_ADMIN_TOKEN1 GW_ADMIN_TOKEN2

admin_env=$(cat <<EOF
# Gateway admin credentials — do NOT commit, do NOT share.
# Consumed by /etc/gateway/config.yaml at install time (copied by step-07).
# File mode is 0600 and owner root:gateway.
ADMIN_SLUG=${GW_ADMIN_SLUG}
ADMIN_TOKEN1=${GW_ADMIN_TOKEN1}
ADMIN_TOKEN2=${GW_ADMIN_TOKEN2}
EOF
)
stage_write "etc/admin.env" "$admin_env"
chmod_secret "${GW_STAGE_DIR}/etc/admin.env"

# NOTE: we deliberately do NOT log the values here. They appear exactly
# once, in step-07, between the "SAVE THIS ONCE" markers.
log "Admin credentials generated and staged (not shown until finalize)."
