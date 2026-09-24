#!/usr/bin/env bash
set -euo pipefail
: "${AGENTFORGE_API_KEY:?set AGENTFORGE_API_KEY}"
base="${AGENTFORGE_URL:-http://127.0.0.1:8080}"
auth=(-H "Authorization: Bearer $AGENTFORGE_API_KEY" -H 'Content-Type: application/json')
create=$(curl -fsS "${auth[@]}" -X POST "$base/v1/sandboxes" -d '{"image":"python:3.13","cpu":1,"memory_mb":512,"disk_mb":2048,"timeout_seconds":300,"network":{"enabled":false}}')
id=$(jq -r .id <<<"$create")
test "$id" != null
curl -fsS "${auth[@]}" -X POST "$base/v1/sandboxes/$id/exec" -d '{"command":["python","-c","print(42)"]}' | jq -e '.exit_code == 0 and .stdout | contains("42")'
content=$(printf 'hello\n' | base64 -w0)
curl -fsS "${auth[@]}" -X PUT "$base/v1/sandboxes/$id/files" -d "{\"path\":\"/workspace/hello.txt\",\"content_base64\":\"$content\"}" | jq -e '.status == "written"'
curl -fsS "${auth[@]}" "$base/v1/sandboxes/$id/files?path=/workspace/hello.txt" | jq -e '.content_base64'
snapshot=$(curl -fsS "${auth[@]}" -X POST "$base/v1/sandboxes/$id/snapshots" -d '{}')
snapshot_id=$(jq -r .id <<<"$snapshot")
restored=$(curl -fsS "${auth[@]}" -X POST "$base/v1/snapshots/$snapshot_id/restore" -d '{}')
restored_id=$(jq -r .id <<<"$restored")
curl -fsS "${auth[@]}" -X DELETE "$base/v1/sandboxes/$restored_id" | jq -e '.status == "destroyed"'
curl -fsS "${auth[@]}" -X DELETE "$base/v1/sandboxes/$id" | jq -e '.status == "destroyed"'
printf 'AgentForge smoke test passed for sandbox %s\n' "$id"
