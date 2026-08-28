# Autoresearch: webBenchmark client throughput (bandwidth saturation)

## Objective
Optimize the Go web benchmark tool (`main.go` + helpers) so a single client
process squeezes maximum download bandwidth out of the wire ("榨干宽带上限")
against a fast HTTP/1.1 server, without memory leaks. Load-testing tool only;
used against one's own CTF/lab targets.

## Metrics
- **Primary**: `throughput_mbps` (MB/s ×8, higher is better) — aggregate download bandwidth measured at the server.
- **Secondary**: `reqs_per_sec` — request rate (higher better, watch for tradeoffs).

## How to Run
`./.auto/measure.sh` — builds client + bench server, serves 1MB payloads from
`127.0.0.1:18081`, runs client at `-c 64 -t 4s`, emits `METRIC` lines.

Bench server source: `.auto/server/main.go` (never the bottleneck; fixed size
body, no per-request allocation, counts bytes served).

## Files in Scope
- `main.go` — flags, transport construction, worker loop (`goFun`), request building, stats loop.
- `Stats.go` — live CPU/mem/load/NIC display (1Hz, off hot path).
- `Utils.go` — random header/IP generators, target URL storage, header list flag.
- `Subscribe.go`, `HandleHttpLocation.go`, `Nslookup.go` — control-plane, off hot path.
- `go.mod` — dependency versions.

## Off Limits
- `.auto/` benchmark harness (edit only to add signal, never to game the metric).
- No cheating: server stays single-threaded simple, fixed 1MB body, loopback.
- Correctness of the tool as a real-world benchmarker: keep the flags, keep
  random-header "CTF" flavor (cookie/UA/XFF defaults), keep retry/timeout behavior.
- No memory leaks: bodies drained, conns closed, no unbounded caches.

## Constraints
- Must still build with `go build ./...`.
- Keep the CLI surface (`-s -c -t -p -r -d -f -sub -i -H -timeout -h`).
- No new dependencies unless clearly justified.

## What's Been Tried
(none yet — baseline pending)
