package main

// Raw TLS HTTP client (no net/http): manual GET + Content-Length read loop
// over TLS, to isolate net/http-over-TLS machinery from the raw TLS path.
import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	conc = flag.Int("c", 64, "connections")
	dur  = flag.Duration("t", 6*time.Second, "duration")
	addr = flag.String("addr", "127.0.0.1:18096", "server addr")
)

var total atomic.Uint64

func main() {
	flag.Parse()
	cfg := &tls.Config{InsecureSkipVerify: true}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := tls.Dial("tcp", *addr, cfg)
			if err != nil {
				return
			}
			defer c.Close()
			req := []byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
			hdr := make([]byte, 0, 4096)
			buf := make([]byte, 65536)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := c.Write(req); err != nil {
					return
				}
				// Read headers until \r\n\r\n, capture Content-Length.
				hdr = hdr[:0]
				cl := 0
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					hdr = append(hdr, buf[:n]...)
					if idx := index(hdr, "\r\n\r\n"); idx >= 0 {
						rest := hdr[idx+4:]
						hdr = hdr[:idx+4]
						cl = contentLength(hdr)
						if len(rest) > 0 {
							total.Add(uint64(len(rest)))
							cl -= len(rest)
						}
						break
					}
				}
				// Drain the body.
				n, err := io.CopyN(io.Discard, c, int64(cl))
				if err != nil {
					return
				}
				total.Add(uint64(n))
			}
		}()
	}
	time.Sleep(*dur)
	close(stop)
	wg.Wait()
	fmt.Printf("RAWTLSTOTAL bytes=%d\n", total.Load())
}

func index(b []byte, s string) int {
	for i := 0; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == s {
			return i
		}
	}
	return -1
}

func contentLength(hdr []byte) int {
	s := string(hdr)
	for {
		i := index([]byte(s), "\r\n")
		if i < 0 {
			break
		}
		line := s[:i]
		s = s[i+2:]
		if len(line) > 15 && line[:15] == "Content-Length:" {
			n, _ := strconv.Atoi(strings.TrimSpace(line[15:]))
			return n
		}
	}
	return 0
}

