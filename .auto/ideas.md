# Deferred ideas (webBenchmark bandwidth)

- **Raw pipelined HTTP/1.1 mode**: a hand-rolled client that pipelines N GETs per
  connection (write request, don't wait) and reads responses continuously.
  My quick raw prototype was slower than net/http (49K vs 56K rps) because of
  naive header parsing, but a well-buffered pipelined version could beat
  net/http on high-latency real links (RTT-bound, where per-request CPU is
  irrelevant). Add only if a real-WAN test shows net/http can't fill the pipe.
- **Socket buffer tuning (SO_RCVBUF/SO_SNDBUF 1-4MB) via Dialer.Control**:
  untested here; loopback was OS-capped so it wouldn't show. May matter on real
  high-BDP links. Needs per-OS build-tagged syscall code (linux + windows).
- **Auto-concurrency**: pick -c so aggregate in-flight bytes ≈ BDP (RTT×BW).
  Over-engineering for a CTF tool; skip unless users complain.
- **Benchmark against a real remote server**: the loopback harness can't
  resolve sub-15% client changes. A WAN or 10G-LAN target would give the client
  code room to matter. Do this before any further client optimization.
- **GC tuning (GOGC / GOMEMLIMIT)**: the c=64→256 rps penalty (~15%) is partly
  GC/alloc driven; try GOGC=200 or GOMEMLIMIT to shrink the penalty if high -c
  usage matters.
