// Raw TCP HTTP/1.1 client: N persistent conns, GET, read full body, buffer reused.
// Measures the raw server+OS ceiling without net/http overhead or per-req allocs.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	addr = flag.String("addr", "127.0.0.1:18081", "server addr")
	conc = flag.Int("c", 64, "connections")
	dur  = flag.Duration("t", 4*time.Second, "run duration")
	size = flag.Int("size", 1<<20, "expected body size")
)

var total atomic.Uint64

func worker(id int, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		return
	}
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 1<<20)
	req := []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
	body := make([]byte, *size)
	for {
		select {
		case <-stop:
			return
		default:
		}
		if _, err := conn.Write(req); err != nil {
			return
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		if _, err := io.ReadFull(reader, body); err != nil {
			return
		}
		total.Add(uint64(len(body)))
	}
}

func main() {
	flag.Parse()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go worker(i, stop, &wg)
	}
	time.Sleep(*dur)
	close(stop)
	wg.Wait()
	fmt.Printf("SERVED raw-bench bytes=%d\n", total.Load())
}
