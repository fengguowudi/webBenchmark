// Bench server: serves a fixed-size body as fast as possible, counts bytes,
// auto-exits after -runtime and prints SERVED stats. Measures client-side
// aggregate throughput (download bandwidth) of the benchmark tool.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

var (
	addr     = flag.String("addr", "127.0.0.1:18081", "listen address")
	size     = flag.Int("size", 1<<20, "payload bytes per response")
	runtime  = flag.Duration("runtime", 9*time.Second, "how long to serve")
	body     []byte
	bytesOut atomic.Uint64
	requests atomic.Uint64
)

func handler(w http.ResponseWriter, r *http.Request) {
	requests.Add(1)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	n, _ := w.Write(body)
	bytesOut.Add(uint64(n))
}

func main() {
	flag.Parse()
	body = make([]byte, *size)
	for i := range body {
		body[i] = byte(i)
	}
	srv := &http.Server{Addr: *addr, Handler: http.HandlerFunc(handler)}
	go func() {
		_ = srv.ListenAndServe()
	}()
	time.Sleep(*runtime)
	_ = srv.Close()
	fmt.Printf("SERVED bytes=%d requests=%d\n", bytesOut.Load(), requests.Load())
}
