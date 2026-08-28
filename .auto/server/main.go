package main

// copy of bench server with cpuprofile support
import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime/pprof"
	"sync/atomic"
	"time"
)

var (
	addr    = flag.String("addr", "127.0.0.1:18083", "listen address")
	size    = flag.Int("size", 1<<20, "payload bytes per response")
	runtime = flag.Duration("runtime", 9*time.Second, "how long to serve")
	prof    = flag.String("cpuprofile", "", "write cpu profile")
	body    []byte
	bytesOut atomic.Uint64
	requests atomic.Uint64
	contentLength string
)

func handler(w http.ResponseWriter, r *http.Request) {
	requests.Add(1)
	w.Header().Set("Content-Length", contentLength)
	n, _ := w.Write(body)
	bytesOut.Add(uint64(n))
}

func main() {
	flag.Parse()
	if *prof != "" {
		f, _ := os.Create(*prof)
		pprof.StartCPUProfile(f)
		defer func() { pprof.StopCPUProfile(); f.Close() }()
	}
	body = make([]byte, *size)
	contentLength = fmt.Sprintf("%d", len(body))
	for i := range body {
		body[i] = byte(i)
	}
	srv := &http.Server{Addr: *addr, Handler: http.HandlerFunc(handler)}
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(*runtime)
	_ = srv.Close()
	fmt.Printf("SERVED bytes=%d requests=%d\n", bytesOut.Load(), requests.Load())
}
