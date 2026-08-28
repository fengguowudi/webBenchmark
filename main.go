package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/apoorvam/goterminal"
)

const (
	defaultConcurrency = 16
	defaultTimeout     = 10 * time.Second
	retryDelay         = 25 * time.Millisecond
	maxIdleConnections = 1024
)

var (
	help           = flag.Bool("h", false, "show this help")
	concurrency    = flag.Int("c", defaultConcurrency, "number of concurrent workers")
	targetURLFlag  = flag.String("s", "", "target URL (required unless -sub is used)")
	postContent    = flag.String("p", "", "POST content; GET is used when empty")
	referer        = flag.String("r", "", "Referer URL")
	detectLocation = flag.Bool("d", false, "use the target's Location header")
	xforwardfor    = flag.Bool("f", true, "send randomized X-Forwarded-For and X-Real-IP headers")
	subscribe      = flag.String("sub", "", "URL returning the current target URL")
	requestTimeout = flag.Duration("timeout", defaultTimeout, "per-request timeout")
	runFor         = flag.Duration("t", 0, "stop after this duration; 0 means Ctrl-C")

	terminalWriter = goterminal.New(os.Stdout)
	customIP       ipArray
	headers        headersList
)

func usage() {
	fmt.Fprintf(os.Stderr, `webBenchmark 1.0
Usage: webBenchmark -s URL [options]

`)
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, `
Examples:
  webBenchmark -c 128 -s https://target.example -t 30s
  webBenchmark -c 256 -s https://target.example -i 192.0.2.10 -i 192.0.2.11
  webBenchmark -c 128 -sub https://controller.example/target -d
`)
}

func validateFlags() error {
	if *concurrency <= 0 {
		return fmt.Errorf("-c must be greater than zero")
	}
	if *requestTimeout <= 0 {
		return fmt.Errorf("-timeout must be greater than zero")
	}
	if *runFor < 0 {
		return fmt.Errorf("-t cannot be negative")
	}
	if strings.TrimSpace(*targetURLFlag) == "" && strings.TrimSpace(*subscribe) == "" {
		return fmt.Errorf("-s or -sub is required")
	}
	if raw := strings.TrimSpace(*targetURLFlag); raw != "" {
		if err := validateTargetURL(raw); err != nil {
			return fmt.Errorf("invalid -s: %w", err)
		}
	}
	if raw := strings.TrimSpace(*subscribe); raw != "" {
		if err := validateTargetURL(raw); err != nil {
			return fmt.Errorf("invalid -sub: %w", err)
		}
	}
	return nil
}

func main() {
	// High-throughput benchmark tool: fewer GC cycles at high -c costs only heap,
	// which is cheap here. Respect an explicit GOGC env override.
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(400)
	}
	flag.Var(&customIP, "i", "custom destination IP; may be repeated")
	flag.Var(&headers, "H", "custom header (Key:Value); RandomN generates N letters")
	flag.Usage = usage
	flag.Parse()

	if *help {
		usage()
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *runFor > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *runFor)
		defer cancel()
	}

	initialTarget := strings.TrimSpace(*targetURLFlag)
	if *subscribe != "" {
		var err error
		initialTarget, err = Subscribe(ctx, strings.TrimSpace(*subscribe))
		if err != nil {
			fmt.Fprintln(os.Stderr, "subscription:", err)
			return
		}
	}
	if *detectLocation {
		if location := GetHttpLocation(ctx, initialTarget); location != "" {
			initialTarget = location
		}
	}
	if err := validateTargetURL(initialTarget); err != nil {
		fmt.Fprintln(os.Stderr, "target:", err)
		return
	}
	setTargetURL(initialTarget)

	if *subscribe != "" {
		go subscribeUpdate(ctx, strings.TrimSpace(*subscribe), *detectLocation)
	} else if *detectLocation {
		go RefreshHttpLocation(ctx, initialTarget)
	}

	transport := buildTransport(customIP)
	client := &http.Client{Transport: transport, Timeout: *requestTimeout}
	defer transport.CloseIdleConnections()

	go showStat(ctx)

	var waitGroup sync.WaitGroup
	for workerID := 0; workerID < *concurrency; workerID++ {
		waitGroup.Add(1)
		go goFun(ctx, client, *postContent, *referer, *xforwardfor, headers, workerID, &waitGroup)
	}
	waitGroup.Wait()
	terminalWriter.Reset()
}

func buildTransport(customIPs ipArray) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: func(_, _ string, c syscall.RawConn) error { return tuneSocket(c) }}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // CTF endpoints often use self-signed TLS.
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          maxIdleConnections,
		MaxIdleConnsPerHost:   maxIdleConnections,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
	}

	if len(customIPs) == 0 {
		return transport
	}

	var ipIndex atomic.Uint64
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		ip := customIPs[ipIndex.Add(1)%uint64(len(customIPs))]
		return dialer.DialContext(ctx, network, formatDialAddr(addr, ip))
	}
	return transport
}

func formatDialAddr(addr, ip string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(ip) == nil {
		return addr
	}
	return net.JoinHostPort(ip, port)
}

func goFun(ctx context.Context, client *http.Client, postContent, referer string, xforwardFor bool, customHeaders headersList, workerID int, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	randSource := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
	for ctx.Err() == nil {
		request, err := buildRequest(currentTargetURL(), postContent, referer, xforwardFor, customHeaders, randSource)
		if err == nil {
			response, requestErr := client.Do(request)
			drainResponse(response)
			if requestErr == nil {
				continue
			}
		}
		if !waitFor(ctx, retryDelay) {
			return
		}
	}
}

func drainResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
}

func waitFor(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func buildRequest(target, post, referer string, xforwardFor bool, customHeaders headersList, randSource *rand.Rand) (*http.Request, error) {
	method := http.MethodGet
	var body io.Reader
	if post != "" {
		method = http.MethodPost
		body = strings.NewReader(post)
	}

	request, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, err
	}
	if referer == "" {
		referer = target
	}
	request.Header.Set("Cookie", RandStringBytesMaskImpr(12, randSource))
	request.Header.Set("User-Agent", randomUserAgent(randSource))
	request.Header.Set("Referer", referer)
	if xforwardFor {
		randomIP := generateRandomIPAddress(randSource)
		request.Header.Set("X-Forwarded-For", randomIP)
		request.Header.Set("X-Real-IP", randomIP)
	}
	applyCustomHeaders(request, customHeaders, randSource)
	return request, nil
}

func applyCustomHeaders(request *http.Request, customHeaders headersList, randSource *rand.Rand) {
	for _, header := range customHeaders {
		request.Header.Set(randomValue(header.key, randSource), randomValue(header.value, randSource))
	}
}

func randomUserAgent(randSource *rand.Rand) string {
	return userAgents[randSource.Intn(len(userAgents))]
}
