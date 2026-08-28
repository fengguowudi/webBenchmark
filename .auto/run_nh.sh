#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
./benchserver.exe -addr 127.0.0.1:18101 -size 1048576 -runtime 12s -tls > nh.log 2>&1 &
SRV=$!
for _ in $(seq 1 40); do (exec 3<>/dev/tcp/127.0.0.1/18101) 2>/dev/null && break; sleep 0.2; done
RBS=${1:-4096}
./nhclient.exe -c 64 -t 5s -addr 127.0.0.1:18101 -rbs $RBS > nhclient.txt
wait $SRV 2>/dev/null
B=$(sed -n 's/.*bytes=\([0-9]*\).*/\1/p' nhclient.txt)
G=$(awk "BEGIN{printf \"%.2f\", $B*8/1e6/5}")
echo "ReadBufferSize=$RBS: $G Gbps (client bytes=$B)"
grep SERVED nh.log
rm -f nh.log nhclient.txt
