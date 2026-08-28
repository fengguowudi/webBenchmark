#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

DUR=${DUR:-8}      # client run seconds (longer = less loopback noise)
CONC=${CONC:-64}    # client concurrency (env override)
PORT=18081
SIZE=${SIZE:-1048576} # payload bytes (env override); 1MB = bandwidth-saturation regime (goal), stable +/-1.5%

# Fast pre-check: client must compile.
go build -o .auto/wb.exe . || { echo "CLIENT_BUILD_FAILED"; exit 1; }
go build -o .auto/benchserver.exe ./.auto/server || { echo "SERVER_BUILD_FAILED"; exit 1; }

# Start server (auto-exits after DUR+5s, outlives the client window).
./.auto/benchserver.exe -addr 127.0.0.1:$PORT -size $SIZE -runtime $((DUR+5))s > .auto/server.log 2>&1 &
SRV=$!

# Wait for the port to accept connections.
READY=0
for _ in $(seq 1 50); do
  if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then
    exec 3>&- 3<&- 2>/dev/null || true
    READY=1
    break
  fi
  sleep 0.1
done
if [ "$READY" != 1 ]; then
  echo "SERVER_NOT_READY"
  kill "$SRV" 2>/dev/null || true
  exit 1
fi

# Run the benchmark client for DUR seconds, silence its UI.
./.auto/wb.exe -s http://127.0.0.1:$PORT -c $CONC -t ${DUR}s >/dev/null 2>&1 || true

# Wait for server to finish and print stats.
wait "$SRV" 2>/dev/null || true

BYTES=$(sed -n 's/.*bytes=\([0-9]*\).*/\1/p' .auto/server.log | head -1)
REQS=$(sed -n 's/.*requests=\([0-9]*\).*/\1/p' .auto/server.log | head -1)
if [ -z "${BYTES:-}" ] || [ -z "${REQS:-}" ]; then
  echo "NO_SERVER_STATS"; cat .auto/server.log; exit 1
fi

MBPS=$(awk "BEGIN{printf \"%.2f\", $BYTES*8/1e6/$DUR}")
RPS=$(awk "BEGIN{printf \"%.0f\", $REQS/$DUR}")
echo "METRIC throughput_mbps=$MBPS"
echo "METRIC reqs_per_sec=$RPS"
