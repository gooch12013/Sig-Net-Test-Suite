#!/usr/bin/env bash
# Smoke test for `sig-net --mcp`: the handshake, the tool list, a read-only call, and the read-only refusal.
# Needs no network, so CI runs it on macOS, Linux and Windows.
set -euo pipefail
cd "$(dirname "$0")/.."

out=$(printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_tids","arguments":{"family":"Endpoint"}}}' \
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"set_parameter","arguments":{"device":"7FF000000001","tid":"RT_DEVICE_LABEL","value":"x"}}}' \
    | swift run --quiet sig-net --mcp)

expect() { grep -q -- "$1" <<<"$out" || { echo "mcp-smoke: no $2 in:"; echo "$out"; exit 1; }; }
expect '"serverInfo"' "initialize result"
expect '"name":"virtual_device"' "virtual_device in tools/list"
expect 'EP_PROTOCOL' "EP_PROTOCOL in list_tids"
expect 'started read-only' "read-only refusal of set_parameter"
echo "mcp-smoke: ok"
