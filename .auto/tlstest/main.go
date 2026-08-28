package main

// Pure TLS record throughput (no HTTP): isolates TLS crypto ceiling from
// HTTP-over-TLS request machinery. stdlib only.
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

var (
	conc = flag.Int("c", 4, "connection pairs")
	dur  = flag.Duration("t", 4*time.Second, "duration")
	port = flag.Int("port", 18095, "base port")
)

var total atomic.Uint64

func makeCert() tls.Certificate {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func main() {
	flag.Parse()
	cert := makeCert()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < *conc; i++ {
		p := *port + i
		ln, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p), cfg)
		if err != nil {
			panic(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			io.Copy(io.Discard, c)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p), &tls.Config{InsecureSkipVerify: true})
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
	fmt.Printf("TLSTOTAL bytes=%d\n", total.Load())
}
