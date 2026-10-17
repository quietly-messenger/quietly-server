// Package push delivers content-free wakeups to a device's UnifiedPush
// endpoint (PROTOCOL.md §13.3). The push provider learns only that *some*
// device has *something* waiting.
package push

import (
	"context"
	"net/http"
	"strings"
)

// Wake POSTs a content-free wakeup to a UnifiedPush endpoint.
func Wake(ctx context.Context, client *http.Client, endpoint string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(`{"v":"quietly/1","type":"wake"}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
