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

## Correction (#28, robust harness)
- Machine loopback wall is ~38-41 Gbps (hot window), not the old 35-37 estimate
  (single-run, cooler machine). Pure-TCP diagnostic test trails the HTTP path by
  ~5-10% (1MB-chunk write loop + shorter 4s window). Tool at c=4 sustains 38-41.
- Robust-harness capability picture: peak ~38-41 @ c=4, metric ~33.5 @ c=64 (1MB).
