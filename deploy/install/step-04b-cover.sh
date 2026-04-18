#!/usr/bin/env bash
# step-04b-cover.sh — Door-only: cover asset + initial slug.
#
# Only runs when GW_NODE_TYPE == "door". The door presents a benign cover on
# `/` and issues a 302 redirect on `/<slug>` to a healthy mirror chosen by
# the hub. This step asks:
#
#   1. Which kind of cover to serve
#        static_file       — any binary/image asset (e.g. cat.jpg)
#        static_html       — an HTML file
#        passthrough_404   — no cover; server returns a default 404
#   2. For static_file / static_html — where is the source file?
#   3. Generates one initial slug (32 hex chars) and stages it for step-07.
#
# Outputs (env):
#   GW_COVER_KIND              static_file | static_html | passthrough_404
#   GW_COVER_PATH              absolute path on the operator's machine
#                              (only when kind != passthrough_404)
#   GW_COVER_STAGED_NAME       basename of the staged file under /etc/gateway/cover/
#   GW_DOOR_SLUG               the auto-generated initial slug
#
# Outputs (staged files):
#   <stage>/etc/cover/<name>         (mode 0644) — only for static_*
#   <stage>/etc/door-config.yaml     (mode 0640) — door-specific config snippet
#                                    that step-07 merges into config.yaml
#
# Bash >= 4.
set -euo pipefail

# shellcheck disable=SC1091
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

step_banner "Step 4b/7  Door cover + initial slug"

# Hard gate: this step is door-only. If sourced when GW_NODE_TYPE is
# something else, emit a warn and return early so the install flow
# continues unchanged.
if [[ "${GW_NODE_TYPE:-}" != "door" ]]; then
    log "Skipping cover setup (node type: ${GW_NODE_TYPE:-<unset>})"
    return 0 2>/dev/null || exit 0
fi

stage_init

# ---------------------------------------------------------------------------
# Locate the default blank.html bundled with the repo. If the operator
# chose static_file/static_html and didn't give a path, we fall back to
# this.
# ---------------------------------------------------------------------------
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_deploy="$(cd -- "$script_dir/.." && pwd)"   # gateway/deploy
default_cover="$repo_deploy/cover/blank.html"

# ---------------------------------------------------------------------------
# Validator for a cover-kind value.
# ---------------------------------------------------------------------------
validate_cover_kind() {
    case "$1" in
        static_file|static_html|passthrough_404) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Ask for the cover kind (or accept flag).
# ---------------------------------------------------------------------------
if [[ -n "${GW_COVER_KIND:-}" ]]; then
    if ! validate_cover_kind "$GW_COVER_KIND"; then
        die "invalid --cover-kind: $GW_COVER_KIND"
    fi
    log "Cover kind (from flag): $GW_COVER_KIND"
else
    choice="$(ask_choice 'Select cover asset kind:' \
        'static_file       — serve any file (e.g. cat.jpg)' \
        'static_html       — serve an HTML landing page' \
        'passthrough_404   — no cover; return a default 404')"
    case "$choice" in
        static_file*)     GW_COVER_KIND=static_file     ;;
        static_html*)     GW_COVER_KIND=static_html     ;;
        passthrough_404*) GW_COVER_KIND=passthrough_404 ;;
        *) die "unexpected cover kind: $choice" ;;
    esac
    export GW_COVER_KIND
fi

# ---------------------------------------------------------------------------
# Resolve / validate the cover source path (only for static_*).
# ---------------------------------------------------------------------------
cover_staged_name=""
if [[ "$GW_COVER_KIND" != "passthrough_404" ]]; then
    if [[ -z "${GW_COVER_PATH:-}" ]]; then
        if [[ "${GW_NONINTERACTIVE:-0}" == "1" ]]; then
            # In non-interactive mode, fall back to the bundled blank.html
            # for static_html and fail loudly for static_file (no sensible
            # default for an arbitrary asset).
            if [[ "$GW_COVER_KIND" == "static_html" ]]; then
                GW_COVER_PATH="$default_cover"
                info "Using bundled default: $default_cover"
            else
                die "cover-kind=static_file requires --cover-path=<file>"
            fi
        else
            info "Provide a path to the file the door should serve as its cover."
            info "Press Enter to use the bundled default ($default_cover)."
            GW_COVER_PATH="$(ask_free 'Cover source file path' "$default_cover")"
        fi
        export GW_COVER_PATH
    fi

    if [[ ! -f "$GW_COVER_PATH" ]]; then
        die "cover source file not found: $GW_COVER_PATH"
    fi
    if [[ ! -r "$GW_COVER_PATH" ]]; then
        die "cover source file not readable: $GW_COVER_PATH"
    fi

    # Stage under <stage>/etc/cover/<basename>. Keep the original basename
    # so the operator can reason about what landed in /etc/gateway/cover/.
    cover_staged_name="$(basename -- "$GW_COVER_PATH")"
    # Strip path traversal just in case (basename already does, but belt+braces).
    cover_staged_name="${cover_staged_name//\//_}"
    mkdir -p "${GW_STAGE_DIR}/etc/cover"
    install -m 0644 -- "$GW_COVER_PATH" \
        "${GW_STAGE_DIR}/etc/cover/${cover_staged_name}"
    log "Staged cover asset: ${cover_staged_name} ($(wc -c < "${GW_STAGE_DIR}/etc/cover/${cover_staged_name}") bytes)"
else
    info "passthrough_404 selected — no cover asset will be staged."
fi
export GW_COVER_STAGED_NAME="$cover_staged_name"

# ---------------------------------------------------------------------------
# Generate one initial slug. More can be added later via admin API.
# 32 bytes of hex = 64 chars. The spec calls for "<32-char-random>" which
# we interpret as 32 bytes of entropy (rand_hex 32 returns 64 hex chars).
# ---------------------------------------------------------------------------
GW_DOOR_SLUG="${GW_DOOR_SLUG:-$(rand_hex 32)}"
export GW_DOOR_SLUG

# ---------------------------------------------------------------------------
# Write a door-specific config snippet that step-07 will merge into
# config.yaml. Keeping it as a separate staged file keeps step-07 agnostic
# to the cover/slug vocabulary.
# ---------------------------------------------------------------------------
# Decide content_type hints — only used for static_file. For static_html
# we hard-code text/html; for others we leave blank so the binary's
# default kicks in.
cover_content_type=""
if [[ "$GW_COVER_KIND" == "static_html" ]]; then
    cover_content_type="text/html; charset=utf-8"
elif [[ "$GW_COVER_KIND" == "static_file" ]]; then
    # Best-effort sniff via `file` if available; otherwise let the binary
    # guess from the extension at serve time.
    if have file; then
        cover_content_type="$(file --brief --mime-type -- \
            "${GW_STAGE_DIR}/etc/cover/${cover_staged_name}" 2>/dev/null || true)"
    fi
fi

door_cfg=$(cat <<DOORCFG
# Door-specific snippet — merged into config.yaml by step-07-finalize.
# Written by step-04b-cover.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
cover:
  enabled: $([[ "$GW_COVER_KIND" == "passthrough_404" ]] && printf 'false' || printf 'true')
  kind: ${GW_COVER_KIND}
$(
if [[ "$GW_COVER_KIND" != "passthrough_404" ]]; then
    printf '  path: /etc/gateway/cover/%s\n' "$cover_staged_name"
    if [[ -n "$cover_content_type" ]]; then
        printf '  content_type: "%s"\n' "$cover_content_type"
    fi
    cat <<HEADERS
  headers:
    Cache-Control: "public, max-age=3600"
HEADERS
fi
)
slugs:
  - slug: "${GW_DOOR_SLUG}"
    strategy: random
    target_tenants: []
    status: 302
    exclude_regions: []
DOORCFG
)

stage_write "etc/door-config.yaml" "$door_cfg"
chmod 640 "${GW_STAGE_DIR}/etc/door-config.yaml"

log "Door configuration staged (cover=${GW_COVER_KIND}, 1 initial slug)."
log "Step 4b complete."
