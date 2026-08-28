package main

// Pure TCP throughput test on loopback: N pairs, sender writes 1MB buffers, receiver discards.
import (
	"flag"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	conc = flag.Int("c", 4, "connection pairs")
	dur  = flag.Duration("t", 4*time.Second, "duration")
	port = flag.Int("port", 18090, "base port")
)

var total atomic.Uint64

func main() {
	flag.Parse()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < *conc; i++ {
		p := *port + i
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			panic(err)
		}
		defer ln.Close()
		// receiver
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			io.Copy(io.Discard, c)
		}()
		// sender
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				return
			}
			buf := make([]byte, 1<<20)
			for {
				select {
				case <-stop:
					return
				default:
				}
				n, err := c.Write(buf)
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
	fmt.Printf("TCPTOTAL bytes=%d\n", total.Load())
}
