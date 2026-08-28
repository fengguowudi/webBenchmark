# Deferred ideas (webBenchmark bandwidth) — FINAL STATE

All loopback-verifiable hypotheses have been measured (22 experiments). The
following remain, all requiring something this harness cannot provide:
- **Real-WAN / 10G-LAN benchmark** (the one real next step): the loopback
  harness cannot resolve sub-drift client changes on real links. Point the
  harness at a real remote server and re-run the kept optimizations there.
- **Raw pipelined HTTP/1.1 mode**: only if a real-WAN test shows net/http
  cannot fill the pipe with multiple connections. Risky (chunked parsing,
  server support), marginal on loopback — do not build speculatively.
- **Auto-concurrency**: over-engineering for a CTF tool; the `-c` flag
  already covers every concurrency level. Skip unless users complain.

## Done (this session, kept)
- Socket buffers (2MB SO_RCVBUF/SO_SNDBUF, best-effort): +47-53% validated
- GOGC=400: +4% at high concurrency
- Robustness: best-effort tuning never fails dials; all 3 shipped targets build

## Done (this session, measured/discarded)
- ReadBufferSize (negative), IP builder (noise), TCP-reference normalization
  (disproven), timeout machinery (free — default kept), transport sharding,
  URL-cache/Clone (neutral/negative), drain pooling (neutral),
  GOMEMLIMIT (neutral, #22)

## Conclusion
webBenchmark on this box: 19.4 → ~30-36.5 Gbps loopback (depending on -c),
leak-free, robust, release-ready. The bottleneck everywhere is the machine
(loopback TCP / CPU), not the tool.

## Correction (#28-#29, robust harness)
- Machine loopback wall: ~38 Gbps (8s pure-TCP median, same-window). Old 35-37
  estimate was single-run/cooler-machine. The 38-41 range seen in #27/#28 was
  window drift between measurements, NOT a higher wall - same-window HTTP c=4
  (37.9) == pure-TCP 8s (38.1) within 1%. Tool saturates the wall exactly.
- Use 8s windows for diagnostics (4s under-samples startup); always same-window
  interleaving for any wall-vs-http comparison.
- Robust-harness capability picture: wall/peak ~38 @ c=4, metric ~33.5 @ c=64.

## Capability picture (complete, uniform robust methodology, #33)
- 1MB bandwidth regime: wall ~38-40 Gbps (8s pure-TCP, same-window), c=4 peak
  ~39.7, c=64 metric ~32.8-33.5 (spread 2-6%).
- 32KB request-rate regime: ~50.5K rps / 13.2 Gbps at c=16 (spread ~10%,
  CPU-bound, inherently noisier than bandwidth regime).
- Sustained full-load runs are thermally stable (no self-degradation, #32).

## FINAL SESSION STATE (#48)
- Releases: v1.1.0 (socket buffers +47-53%, GOGC=400), v1.1.1 (ForceAttemptHTTP2
  fix: HTTPS +4.8x loopback / +3.2x WAN-RTT / +4.5x request-rate).
- Behavior map (all robust median-of-3, same-window interleaved):
  HTTP 1MB: metric ~30-33.5 Gbps @ c=64, peak ~38 @ c=4; 32KB ~47K rps.
  HTTPS 1MB: ~18.7 @ c=64 (flat c=4-64, c=16 optimal), 32KB ~38K rps.
  Transitions: HTTP 64-128KB, TLS 32-64KB. RTT: 26->14 Gbps @ c=256 (5-100ms).
- Verified: leak-free, thermally stable, robust to target crash (no hang).
- Harness: median-of-3, DELAY (RTT sim), TLS (self-signed) flags.
- ONLY remaining: real-WAN validation against an external target.
