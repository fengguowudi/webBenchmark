// Raw TCP HTTP/1.1 server: reads request, writes one big pre-rendered response.
// Isolates whether net/http's server write path is the throughput ceiling.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

var (
	addr    = flag.String("addr", "127.0.0.1:18082", "listen address")
	size    = flag.Int("size", 1<<20, "payload bytes per response")
	runtime = flag.Duration("runtime", 15*time.Second, "how long to serve")
	bytesOut atomic.Uint64
)

func handle(conn net.Conn, resp []byte) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 4096)
	for {
		// read request head until blank line
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		if _, err := conn.Write(resp); err != nil {
			return
		}
		bytesOut.Add(uint64(len(resp)))
	}
}

func main() {
	flag.Parse()
	body := make([]byte, *size)
	for i := range body {
		body[i] = byte(i)
	}
	resp := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", len(body))), body...)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c, resp)
		}
	}()
	time.Sleep(*runtime)
	ln.Close()
	fmt.Printf("SERVED rawserver bytes=%d\n", bytesOut.Load())
}
