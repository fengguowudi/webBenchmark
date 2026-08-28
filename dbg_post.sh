#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
./.auto/benchserver.exe -addr 127.0.0.1:18111 -size 1048576 -runtime 12s > .auto/dbg.log 2>&1 &
SRV=$!
for _ in $(seq 1 40); do (exec 3<>/dev/tcp/127.0.0.1/18111) 2>/dev/null && break; sleep 0.2; done
POST=$(python -c "print('A'*65536)")
./.auto/wb.exe -s http://127.0.0.1:18111 -c 4 -t 3s -p "$POST" > .auto/dbgclient.log 2>&1
echo "exit: $?"
echo "--- client log ---"; head -8 .auto/dbgclient.log
sleep 1
echo "--- server log ---"; cat .auto/dbg.log
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
rm -f .auto/dbg.log .auto/dbgclient.log
