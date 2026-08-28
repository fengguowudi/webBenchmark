#!/usr/bin/env bash
# A/B: net/http TLS client (wb.exe) vs raw TLS HTTP client (rawtlshttp.exe)
set -uo pipefail
cd "$(dirname "$0")"
SIZE=${SIZE:-1048576}; CONC=${CONC:-64}; PORT=18096; T=${T:-6}
./benchserver.exe -addr 127.0.0.1:$PORT -size $SIZE -runtime $((T+8))s -tls > tls_ab.log 2>&1 &
SRV=$!
for _ in $(seq 1 40); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.2; done
echo "--- raw TLS HTTP client ---"
./rawtlshttp.exe -c $CONC -t ${T}s -addr 127.0.0.1:$PORT
B=$(sed -n 's/.*RAWTLSTOTAL bytes=\([0-9]*\).*/\1/p' /dev/null 2>/dev/null)
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
grep -o 'SERVED bytes=[0-9]*' tls_ab.log | head -1
rm -f tls_ab.log
