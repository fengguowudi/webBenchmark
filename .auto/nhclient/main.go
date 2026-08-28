package main

// net/http TLS client with configurable ReadBufferSize, to test whether the
// small (4KB) transport read buffer is what serializes net/http over TLS.
import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var (
	conc = flag.Int("c", 64, "connections")
	dur  = flag.Duration("t", 6*time.Second, "duration")
	addr = flag.String("addr", "127.0.0.1:18101", "server addr")
	rbs  = flag.Int("rbs", 4096, "transport ReadBufferSize")
)

var total atomic.Uint64

func main() {
	flag.Parse()
	tr := &http.Transport{
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 1024,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		ReadBufferSize:      *rbs,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := client.Get("https://" + *addr + "/")
				if err != nil {
					return
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				total.Add(uint64(n))
			}
		}()
	}
	time.Sleep(*dur)
	close(stop)
	wg.Wait()
	fmt.Printf("NHCLIENT bytes=%d\n", total.Load())
}
