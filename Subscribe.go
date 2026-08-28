package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxSubscriptionBytes = 1 << 20

func Subscribe(ctx context.Context, rawURL string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	response, err := controlClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("subscription returned HTTP %s", response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxSubscriptionBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxSubscriptionBytes {
		return "", fmt.Errorf("subscription response exceeds %d bytes", maxSubscriptionBytes)
	}
	value := strings.TrimSpace(string(body))
	if err := validateTargetURL(value); err != nil {
		return "", fmt.Errorf("subscription returned invalid target: %w", err)
	}
	return value, nil
}

func subscribeUpdate(ctx context.Context, rawURL string, detectLocation bool) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			subURL, err := Subscribe(ctx, rawURL)
			if err != nil {
				continue
			}
			nextTarget := subURL
			if detectLocation {
				if location := GetHttpLocation(ctx, subURL); location != "" {
					nextTarget = location
				}
			}
			if validateTargetURL(nextTarget) == nil {
				setTargetURL(nextTarget)
			}
		}
	}
}
