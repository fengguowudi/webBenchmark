package main

// Pure TCP throughput with optional socket buffer tuning (Windows + Linux via raw syscall).
import (
	"flag"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	conc  = flag.Int("c", 4, "connection pairs")
	dur   = flag.Duration("t", 4*time.Second, "duration")
	port  = flag.Int("port", 18090, "base port")
	bufsz = flag.Int("buf", 0, "SO_RCVBUF/SO_SNDBUF size (0=default)")
)

var total atomic.Uint64

func setBuf(c net.Conn, size int) {
	if size <= 0 {
		return
	}
	if rc, ok := c.(*net.TCPConn); ok {
		raw, _ := rc.SyscallConn()
		raw.Control(func(fd uintptr) {
			windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, size)
			windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, size)
		})
	}
	_ = unsafe.Pointer(nil)
}

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
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			setBuf(c, *bufsz)
			io.Copy(io.Discard, c)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				return
			}
			setBuf(c, *bufsz)
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
