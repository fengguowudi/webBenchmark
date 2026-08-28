#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
./benchserver.exe -addr 127.0.0.1:18098 -size 1048576 -runtime 14s -tls > raw.log 2>&1 &
SRV=$!
for _ in $(seq 1 40); do (exec 3<>/dev/tcp/127.0.0.1/18098) 2>/dev/null && break; sleep 0.2; done
./rawtlshttp.exe -c 64 -t 6s -addr 127.0.0.1:18098
sleep 1
grep -o 'SERVED bytes=[0-9]* requests=[0-9]*' raw.log
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
rm -f raw.log
