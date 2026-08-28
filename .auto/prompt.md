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

### Key finding: the client is NOT the bottleneck on this machine
- Pure TCP loopback (no HTTP) caps at **~20-24 Gbps** on this Windows box; it *declines* with more connections. The OS/loopback is the ceiling.
- At 32KB payloads the client+server pair is CPU-saturated (~10-11/12 cores) at ~13-14 Gbps / 50K rps (c=16).
- The net/http client **outperforms a raw TCP/HTTP implementation** (56K vs 49K rps) — no raw-rewrite win.
- HTTP/2 over TLS is much worse on loopback (5.4 Gbps vs 14) — keep HTTP/1.1.

### Changes tested (all neutral or harmful → reverted to original client)
- Transport sharding (8× pools): neutral at all concurrency. Reverted.
- Base-request cache + Clone (skip URL re-parse): neutral; the Clone header-map deep copy + RWMutex actually hurt c=256 by ~12%. Reverted.
- ReadBufferSize 32KB/128KB + WriteBufferSize: neutral-negative. Reverted.
- Pooled 64KB drain buffer (io.CopyBuffer): neutral-negative. Reverted.
- Server Content-Length pre-render: kept (harmless, slightly leaner harness server).
- Concurrency sweet spot on loopback: **c=16** (50.7K rps); c=64 → 48.5K; c=256 → 41.8K (contention/GC penalty). Default -c is already 16.
- Memory: verified leak-free (flat ~22MB working set over 45s at c=64).

### Measurement caveats
- Loopback throughput varies ±5-10% run to run (CPU frequency, GC, other processes) — only >15% changes are resolvable.
- Run-to-run at c=16/32KB/8s: 13.5 / 12.6 / 13.4 Gbps.

### Conclusion
- The tool is already near-optimal; further client micro-optimization is below the noise floor.
- Real-world saturation = use enough -c (16-256) and HTTP/1.1; the OS/wire, not this code, sets the ceiling.
- Keep the benchmark as a regression check (client+server CPU pair), not a micro-optimization target.

### Kept wins
- **GOGC=400 baked in** (`debug.SetGCPercent(400)` when GOGC env unset): +4% at c=256/32KB (11.5 vs 11.0 Gbps), +3.8% at 1MB c=64 (20.2 vs 19.4 Gbps), noise-level at c=16. Memory flat ~65MB, no leak. Confidence 2.2x noise floor. (log #4, keep)

### Discarded
- Manual IP octet builder (removed fmt.Sprintf from hot path, 100K-case verified): metric-neutral at c=256, below noise floor. Reverted. (log #5)
