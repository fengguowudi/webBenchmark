package main

import (
	"container/list"
	"fmt"
	"math/rand"
	"strings"
)

const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

type speedPair struct {
	index uint64
	speed float64
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var SpeedQueue = list.New()
var SpeedIndex uint64 = 0

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
	res := strings.SplitN(value, ":", 2)
	if len(res) != 2 {
		return nil
	}
	*h = append(*h, header{
		res[0], strings.Trim(res[1], " "),
	})
	return nil
}

type ipArray []string

func (i *ipArray) String() string {
	return strings.Join(*i, ",")
}

func (i *ipArray) Set(value string) (err error) {
	*i = append(*i, strings.TrimSpace(value))
	return nil
}

func RandStringBytesMaskImpr(n int, randSource *rand.Rand) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}

func generateRandomIPAddress(randSource *rand.Rand) string {
	ip := fmt.Sprintf("%d.%d.%d.%d", randSource.Intn(255), randSource.Intn(255), randSource.Intn(255), randSource.Intn(255))
	return ip
}

func LeastSquares(x []float64, y []float64) (a float64, b float64) {
	xi := float64(0)
	x2 := float64(0)
	yi := float64(0)
	xy := float64(0)
	if len(x) != len(y) {
		a = 0
		b = 0
		return
	} else {
		length := float64(len(x))
		for i := 0; i < len(x); i++ {
			xi += x[i]
			x2 += x[i] * x[i]
			yi += y[i]
			xy += x[i] * y[i]
		}
		a = (yi*xi - xy*length) / (xi*xi - x2*length)
		b = (yi*x2 - xy*xi) / (x2*length - xi*xi)
	}
	return
}
