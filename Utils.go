package main

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

const maxRandomHeaderLength = 4096

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var activeTarget atomic.Value

var userAgents = [...]string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.1 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/131.0 Mobile Safari/537.36",
}

type header struct {
	key, value string
}

type headersList []header

func (h *headersList) String() string {
	return fmt.Sprint(*h)
}

func (h *headersList) IsCumulative() bool {
	return true
}

func (h *headersList) Set(value string) error {
	key, headerValue, ok := strings.Cut(value, ":")
	key = strings.TrimSpace(key)
	if !ok || http.CanonicalHeaderKey(key) == "" {
		return fmt.Errorf("header must be Key:Value")
	}
	*h = append(*h, header{key: key, value: strings.TrimSpace(headerValue)})
	return nil
}

type ipArray []string

func (i *ipArray) String() string {
	return strings.Join(*i, ",")
}

func (i *ipArray) Set(value string) error {
	value = strings.TrimSpace(value)
	if net.ParseIP(value) == nil {
		return fmt.Errorf("invalid IP address %q", value)
	}
	*i = append(*i, value)
	return nil
}

func setTargetURL(value string) {
	activeTarget.Store(strings.TrimSpace(value))
}

func currentTargetURL() string {
	value := activeTarget.Load()
	if value == nil {
		return ""
	}
	return value.(string)
}

func validateTargetURL(raw string) error {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		if err == nil {
			err = fmt.Errorf("missing host")
		}
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	return nil
}

func RandStringBytesMaskImpr(n int, randSource *rand.Rand) string {
	if n <= 0 || randSource == nil {
		return ""
	}
	const letterIdxBits = 6
	const letterIdxMask = 1<<letterIdxBits - 1
	const letterIdxMax = 63 / letterIdxBits

	bytes := make([]byte, n)
	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}
		if index := int(cache & letterIdxMask); index < len(letterBytes) {
			bytes[i] = letterBytes[index]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(bytes)
}

func randomValue(value string, randSource *rand.Rand) string {
	const prefix = "Random"
	if !strings.HasPrefix(value, prefix) {
		return value
	}
	length, err := strconv.Atoi(strings.TrimPrefix(value, prefix))
	if err != nil || length < 0 || length > maxRandomHeaderLength {
		return value
	}
	return RandStringBytesMaskImpr(length, randSource)
}

func generateRandomIPAddress(randSource *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d", randSource.Intn(256), randSource.Intn(256), randSource.Intn(256), randSource.Intn(256))
}
