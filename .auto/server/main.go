// Bench server: serves a fixed-size body as fast as possible, counts bytes,
// auto-exits after -runtime and prints SERVED stats. Measures client-side
// aggregate throughput of the benchmark tool. Accepted sockets get 4MB
// buffers (same as the client) so Windows loopback defaults don't cap the test.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

var (
	addr          = flag.String("addr", "127.0.0.1:18081", "listen address")
	size          = flag.Int("size", 1<<20, "payload bytes per response")
	runtime       = flag.Duration("runtime", 14*time.Second, "how long to serve")
	delay         = flag.Duration("delay", 0, "artificial per-request latency (simulates WAN RTT; 0 = off)")
	body          []byte
	contentLength string
	bytesOut      atomic.Uint64
	requests      atomic.Uint64
)

func handler(w http.ResponseWriter, r *http.Request) {
	requests.Add(1)
	if *delay > 0 {
		time.Sleep(*delay)
	}
	w.Header().Set("Content-Length", contentLength)
	n, _ := w.Write(body)
	bytesOut.Add(uint64(n))
}

// tunedListener tunes socket buffers on every accepted connection.
type tunedListener struct {
	net.Listener
}

func (l *tunedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		if rc, err := tc.SyscallConn(); err == nil {
			_ = tuneSocket(rc)
		}
	}
	return c, nil
}

func main() {
	flag.Parse()
	body = make([]byte, *size)
	contentLength = fmt.Sprintf("%d", len(body))
	for i := range body {
		body[i] = byte(i)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		panic(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(handler)}
	go func() {
		_ = srv.Serve(&tunedListener{Listener: ln})
	}()
	time.Sleep(*runtime)
	_ = srv.Close()
	fmt.Printf("SERVED bytes=%d requests=%d\n", bytesOut.Load(), requests.Load())
}
