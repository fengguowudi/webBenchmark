package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"time"
)

const controlRequestTimeout = 10 * time.Second

var (
	controlClient = &http.Client{Timeout: controlRequestTimeout}
	probeClient   = &http.Client{
		Timeout: controlRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func GetHttpLocation(ctx context.Context, rawURL string) string {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	response, err := probeClient.Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))

	location := response.Header.Get("Location")
	if location == "" || response.Request == nil || response.Request.URL == nil {
		return ""
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return response.Request.URL.ResolveReference(parsed).String()
}

func RefreshHttpLocation(ctx context.Context, rawURL string) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if location := GetHttpLocation(ctx, rawURL); location != "" {
				if err := validateTargetURL(location); err == nil {
					setTargetURL(location)
				}
			}
		}
	}
}
