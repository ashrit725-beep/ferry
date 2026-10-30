#!/usr/bin/env bash
# End-to-end Ferry demo on one machine with the real llama.cpp runtime and a
# real open-weight model. The "connected" and "disconnected" sides are two
# directories here; in a real deployment they are separate networks and the
# bundle crosses on the customer's approved media.
#
# Requirements: llama-server on PATH, curl, the model from demo/fetch-model.sh,
# OpenSSL 3 for the independent signature check (optional), and optionally
# .cache/demo-venv with huggingface_hub for the hidden-network-call scenario.
# Set FERRY_DEMO_KEEP=1 to leave the gateway and runtime running afterwards.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FERRY="$ROOT/.venv/bin/ferry"
PY="$ROOT/.venv/bin/python"
MODEL_NAME="qwen2.5-0.5b-instruct"
MODEL_FILE="$ROOT/.cache/upstream/qwen2.5-0.5b-instruct-gguf/qwen2.5-0.5b-instruct-q4_k_m.gguf"
WORK="${FERRY_DEMO_WORK:-$ROOT/demo/work/$(date +%Y%m%d-%H%M%S)}"
LOW="$WORK/connected"
HIGH="$WORK/disconnected"
GW_PORT="${FERRY_DEMO_PORT:-8750}"
RT_PORT="${FERRY_DEMO_RUNTIME_PORT:-8081}"
PIDS=()

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
expect_fail() { if "$@"; then echo "UNEXPECTED: that should have failed"; exit 1; else echo "(failed as expected)"; fi; }
cleanup() {
  if [ "${FERRY_DEMO_KEEP:-0}" = "1" ]; then
    echo "Leaving gateway and runtime running (pids ${PIDS[*]:-none})."
    return
  fi
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
wait_http() { for _ in $(seq 1 240); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 0.5; done; echo "timed out waiting for $1"; exit 1; }
fingerprint() { "$PY" -c 'import sys; from ferry import crypto; print(crypto.key_id(crypto.load_public_key_file(sys.argv[1])))' "$1"; }

command -v llama-server >/dev/null || { echo "llama-server not found (brew install llama.cpp)"; exit 2; }
[ -f "$MODEL_FILE" ] || { echo "Model missing: run demo/fetch-model.sh on a connected machine first"; exit 2; }
mkdir -p "$LOW" "$HIGH"
echo "Demo workspace: $WORK"

# ----------------------------------------------------------------- connected side
step "1. Preflight: a stack with a hidden network call (real huggingface_hub)"
if [ -x "$ROOT/.cache/demo-venv/bin/python" ]; then
  expect_fail "$FERRY" preflight --env HF_HOME="$LOW/hf-home" --md "$LOW/preflight-hidden-call.md" -- \
    "$ROOT/.cache/demo-venv/bin/python" -c \
    "from huggingface_hub import hf_hub_download; hf_hub_download('Qwen/Qwen2.5-0.5B-Instruct-GGUF', 'LICENSE', revision='9217f5db79a29953eb74d5343926648285ec7e67')"
else
  echo "(skipped: create .cache/demo-venv with huggingface_hub to run this scenario)"
fi

step "2. Preflight: llama-server on the local GGUF with --offline"
printf '{"messages":[{"role":"user","content":"Reply with one word: ready"}],"max_tokens":8}' > "$LOW/smoke.json"
"$FERRY" preflight --ready-url "http://127.0.0.1:$((RT_PORT + 1))/health" \
  --request-url "http://127.0.0.1:$((RT_PORT + 1))/v1/chat/completions" --request-json "$LOW/smoke.json" \
  --md "$LOW/preflight-llama.md" -- \
  llama-server -m "$MODEL_FILE" --host 127.0.0.1 --port "$((RT_PORT + 1))" --offline --no-webui -c 2048

step "3. Keys for the publisher and the reviewer (no passphrase: demo only)"
"$FERRY" keygen publisher --out-dir "$LOW/keys" --no-passphrase
"$FERRY" keygen reviewer --out-dir "$LOW/keys" --no-passphrase

step "4. Pack and sign the bundle"
"$FERRY" pack "$ROOT/demo/qwen2.5-0.5b-instruct.bundle.toml" --key "$LOW/keys/publisher.key" --out "$LOW/out"
BUNDLE="$(ls "$LOW"/out/*.ferry.tar)"
"$FERRY" sign "$BUNDLE" --key "$LOW/keys/reviewer.key"

step "5. Independent check without Ferry: OpenSSL and shasum"
OPENSSL=""
for c in /opt/homebrew/opt/openssl@3/bin/openssl /opt/homebrew/bin/openssl /usr/local/bin/openssl openssl; do
  if command -v "$c" >/dev/null 2>&1 && "$c" version 2>/dev/null | grep -Eq '^OpenSSL [3-9]'; then OPENSSL="$c"; break; fi
done
mkdir -p "$LOW/check" && tar -xf "$BUNDLE" -C "$LOW/check"
if [ -n "$OPENSSL" ]; then
  for who in publisher reviewer; do
    kid="$(fingerprint "$LOW/keys/$who.pub.pem")"
    printf '%s: ' "$who"
    "$OPENSSL" pkeyutl -verify -pubin -inkey "$LOW/keys/$who.pub.pem" -rawin \
      -in "$LOW/check/manifest.json" -sigfile "$LOW/check/signatures/$kid.sig"
  done
else
  echo "(no OpenSSL 3 found; macOS LibreSSL cannot verify Ed25519)"
fi
"$PY" -c 'import json,sys; m=json.load(open(sys.argv[1])); print("\n".join(a["sha256"] + "  " + a["path"] for a in m["artifacts"]))' \
  "$LOW/check/manifest.json" > "$LOW/check/SHA256SUMS"
(cd "$LOW/check" && shasum -a 256 -c SHA256SUMS)

step "6. A copy with one flipped byte inside the model is rejected"
mkdir -p "$LOW/trust"
"$FERRY" trust add "$LOW/keys/publisher.pub.pem" --trust-dir "$LOW/trust" --name "Demo publisher" --role publisher
"$FERRY" trust add "$LOW/keys/reviewer.pub.pem" --trust-dir "$LOW/trust" --name "Demo reviewer" --role reviewer
cp "$BUNDLE" "$LOW/tampered.ferry.tar"
"$PY" - "$LOW/tampered.ferry.tar" <<'PYEOF'
import sys, tarfile
path = sys.argv[1]
with tarfile.open(path) as tf:
    member = next(m for m in tf.getmembers() if m.name.endswith(".gguf"))
with open(path, "r+b") as fh:
    fh.seek(member.offset_data + 4096)
    b = fh.read(1); fh.seek(-1, 1); fh.write(bytes([b[0] ^ 0x01]))
print(f"flipped one byte inside {member.name}")
PYEOF
expect_fail "$FERRY" verify "$LOW/tampered.ferry.tar" --trust-dir "$LOW/trust" --require-role publisher --require-role reviewer

step "7. Rehearse: import into a throwaway store and serve it with egress blocked"
"$FERRY" rehearse "$BUNDLE" --trust-dir "$LOW/trust" --require-role publisher --require-role reviewer \
  --md "$LOW/rehearsal.md"

# ----------------------------------------------------------------- the transfer
step "8. Transfer (here: a copy into the disconnected side's inbox)"
DATA="$HIGH/data"
"$FERRY" --data-dir "$DATA" init
"$PY" - "$DATA/ferry.toml" <<'PYEOF'
import sys
p = sys.argv[1]
s = open(p).read().replace('required_roles = ["publisher"]', 'required_roles = ["publisher", "reviewer"]')
open(p, "w").write(s)
PYEOF
cp "$BUNDLE" "$DATA/inbox/"

# ----------------------------------------------------------------- disconnected side
step "9. Trust both signers, checking fingerprints received out of band"
"$FERRY" --data-dir "$DATA" trust add "$LOW/keys/publisher.pub.pem" --name "Demo publisher" --role publisher \
  --expect-fingerprint "$(fingerprint "$LOW/keys/publisher.pub.pem")"
"$FERRY" --data-dir "$DATA" trust add "$LOW/keys/reviewer.pub.pem" --name "Demo reviewer" --role reviewer \
  --expect-fingerprint "$(fingerprint "$LOW/keys/reviewer.pub.pem")"

step "10. Import"
"$FERRY" --data-dir "$DATA" import "$DATA/inbox/$(basename "$BUNDLE")"

step "11. Start llama-server on the imported store file, then the gateway"
"$FERRY" --data-dir "$DATA" runtime llamacpp "$MODEL_NAME" --port "$RT_PORT" > "$WORK/runtime.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$RT_PORT/health"
"$FERRY" --data-dir "$DATA" serve --port "$GW_PORT" > "$WORK/gateway.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$GW_PORT/healthz"
"$FERRY" --data-dir "$DATA" backend check "llamacpp-$MODEL_NAME"

step "12. Two apps, a policy that allows only one of them"
"$FERRY" --data-dir "$DATA" app create report-assistant --environment test --description "Demo app"
"$FERRY" --data-dir "$DATA" app create intruder --environment test --description "Has no permission"
KEY_OK="$("$FERRY" --data-dir "$DATA" app key report-assistant --json | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["api_key"])')"
KEY_NO="$("$FERRY" --data-dir "$DATA" app key intruder --json | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["api_key"])')"
cat > "$WORK/policy.json" <<JSON
{"schema": "ferry.dev/access-policy/v1", "description": "Demo policy",
 "rules": [{"id": "report-assistant-chat", "effect": "allow", "principals": ["app:report-assistant"],
            "actions": ["chat.completions"], "models": ["$MODEL_NAME"], "limits": {"max_tokens": 64}}]}
JSON
"$FERRY" --data-dir "$DATA" policy activate "$WORK/policy.json" --comment "demo"

chat() { curl -sS -o "$WORK/last.json" -w '%{http_code}' "http://127.0.0.1:$GW_PORT/v1/chat/completions" \
  -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
  -d "{\"model\":\"$2\",\"messages\":[{\"role\":\"user\",\"content\":\"In one sentence, what is an air-gapped network?\"}]}"; }

step "13. Allowed: report-assistant asks the imported model"
code="$(chat "$KEY_OK" "$MODEL_NAME")"; echo "HTTP $code"
"$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["choices"][0]["message"]["content"].strip()); print("usage:", d.get("usage"))' "$WORK/last.json"

step "14. Denied before inference: an app without permission, and a model that was never imported"
code="$(chat "$KEY_NO" "$MODEL_NAME")"; echo "intruder -> HTTP $code: $(cat "$WORK/last.json")"
code="$(chat "$KEY_OK" "some-unvetted-model")"; echo "unknown model -> HTTP $code: $(cat "$WORK/last.json")"

step "15. Audit chain and evidence"
"$FERRY" --data-dir "$DATA" audit verify
"$FERRY" --data-dir "$DATA" evidence --format md --out "$WORK/evidence.md"
echo "Evidence report: $WORK/evidence.md"

step "16. Backup the installation and rehearse a restore"
"$FERRY" --data-dir "$DATA" backup --out "$WORK/backup.tar"
"$FERRY" --data-dir "$WORK/restored" restore "$WORK/backup.tar"
"$FERRY" --data-dir "$WORK/restored" audit verify

step "17. Console user (password stored in a 0600 file, not printed)"
"$PY" -c 'import secrets; print(secrets.token_urlsafe(18))' > "$WORK/admin-password.txt"
chmod 600 "$WORK/admin-password.txt"
"$FERRY" --data-dir "$DATA" admin create-user admin --role admin --password-stdin < "$WORK/admin-password.txt"
echo "Console: http://127.0.0.1:$GW_PORT/  user: admin  password file: $WORK/admin-password.txt"
echo
echo "Demo finished. Reports: $LOW/preflight-*.md, $LOW/rehearsal.md, $WORK/evidence.md"
