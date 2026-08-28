#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
./benchserver.exe -addr 127.0.0.1:18100 -size 1048576 -runtime 11s -tls > raw3.log 2>&1 &
SRV=$!
for _ in $(seq 1 40); do (exec 3<>/dev/tcp/127.0.0.1/18100) 2>/dev/null && break; sleep 0.2; done
./rawtlshttp.exe -c 64 -t 5s -addr 127.0.0.1:18100 > raw3client.txt
wait $SRV 2>/dev/null
echo "=== server SERVED ==="; grep SERVED raw3.log
echo "=== client ==="; cat raw3client.txt
rm -f raw3.log raw3client.txt
