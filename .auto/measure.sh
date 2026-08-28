#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

DUR=${DUR:-8}      # client run seconds (longer = less loopback noise)
CONC=${CONC:-64}   # client concurrency (env override)
PORT=18081
SIZE=${SIZE:-1048576} # payload bytes (env override); 1MB = bandwidth-saturation regime (goal)
RUNS=${RUNS:-3}    # passes; median is reported (drift/transient-burst robustness)
DELAY=${DELAY:-0}  # artificial per-request latency in ms (simulates WAN RTT; 0=off)

# Fast pre-check: client must compile.
go build -o .auto/wb.exe . || { echo "CLIENT_BUILD_FAILED"; exit 1; }
go build -o .auto/benchserver.exe ./.auto/server || { echo "SERVER_BUILD_FAILED"; exit 1; }

# One full pass: fresh server + client run, echoes "MBPS RPS".
run_pass() {
  local DELAYARG=""; [ "$DELAY" != "0" ] && DELAYARG="-delay ${DELAY}ms"
  ./.auto/benchserver.exe -addr 127.0.0.1:$PORT -size $SIZE -runtime $((DUR+5))s $DELAYARG > .auto/server.log 2>&1 &
  local SRV=$!
  local READY=0
  for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then
      exec 3>&- 3<&- 2>/dev/null || true
      READY=1
      break
    fi
    sleep 0.1
  done
  if [ "$READY" != 1 ]; then
    kill "$SRV" 2>/dev/null || true
    echo "SERVER_NOT_READY"
    return 1
  fi
  # Run the benchmark client for DUR seconds, silence its UI.
  ./.auto/wb.exe -s http://127.0.0.1:$PORT -c $CONC -t ${DUR}s >/dev/null 2>&1 || true
  # Wait for server to finish and print stats.
  wait "$SRV" 2>/dev/null || true
  local BYTES REQS
  BYTES=$(sed -n 's/.*bytes=\([0-9]*\).*/\1/p' .auto/server.log | head -1)
  REQS=$(sed -n 's/.*requests=\([0-9]*\).*/\1/p' .auto/server.log | head -1)
  if [ -z "${BYTES:-}" ] || [ -z "${REQS:-}" ]; then
    echo "NO_SERVER_STATS"
    return 1
  fi
  awk "BEGIN{printf \"%.2f %d\", $BYTES*8/1e6/$DUR, $REQS/$DUR}"
}

MB=()
RP=()
for _ in $(seq 1 "$RUNS"); do
  OUT=$(run_pass) || { echo "$OUT"; exit 1; }
  set -- $OUT
  MB+=("$1")
  RP+=("$2")
done

median() {
  local arr=("$@") n=${#arr[@]}
  local sorted m
  sorted=$(printf '%s\n' "${arr[@]}" | sort -n)
  m=$(( (n+1)/2 ))
  echo "$sorted" | sed -n "${m}p"
}

echo "METRIC throughput_mbps=$(median "${MB[@]}")"
echo "METRIC reqs_per_sec=$(median "${RP[@]}")"
