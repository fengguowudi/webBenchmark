# Deferred ideas (webBenchmark bandwidth)

- **Raw pipelined HTTP/1.1 mode**: a hand-rolled client that pipelines N GETs per
  connection (write request, don't wait) and reads responses continuously.
  My quick raw prototype was slower than net/http (49K vs 56K rps) because of
  naive header parsing, but a well-buffered pipelined version could beat
  net/http on high-latency real links (RTT-bound, where per-request CPU is
  irrelevant). Add only if a real-WAN test shows net/http can't fill the pipe.
- ~~Socket buffer tuning~~ **DONE + KEPT**: 2MB SO_RCVBUF/SO_SNDBUF (build-tagged, stdlib syscall), 1MB c=64 19.4->32.0 Gbps (+60%). Try 2MB vs 4MB at 1MB: equal; 2MB halves kernel memory.
- **Auto-concurrency**: pick -c so aggregate in-flight bytes ≈ BDP (RTT×BW).
  Over-engineering for a CTF tool; skip unless users complain.
- **Benchmark against a real remote server**: the loopback harness can't
  resolve sub-15% client changes. A WAN or 10G-LAN target would give the client
  code room to matter. Do this before any further client optimization.
- ~~GC tuning (GOGC / GOMEMLIMIT)~~ **DONE**: GOGC=400 baked in (debug.SetGCPercent), +4% at c=256 and +3.8% at 1MB, kept. GOMEMLIMIT variant untested — unlikely to beat GOGC=400; skip.
- ~~Manual XFF IP builder (drop fmt.Sprintf)~~ **DONE + REVERTED**: metric-neutral on loopback (below noise). Re-add only if a real-WAN benchmark shows allocation pressure.
- **Concurrency sweep (1MB, socket-tuned)**: c=4 peaks at 36.5 Gbps, c=64 at 31.7. Loopback-specific (near-zero RTT); on real high-RTT links users still need high -c to fill BDP. No tool change.
