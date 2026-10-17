// Package push delivers content-free wakeups to a device's UnifiedPush
// endpoint (PROTOCOL.md §13.3). The push provider learns only that *some*
// device has *something* waiting.
package push

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/storage"
)

// maxEndpointLen bounds stored push URLs.
const maxEndpointLen = 2048

// ValidateEndpoint rejects endpoints that would turn the server into an SSRF
// probe (audit F-09): only https URLs to public hosts are accepted.
func ValidateEndpoint(raw string) error {
	if len(raw) > maxEndpointLen {
		return errors.New("push endpoint too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid push endpoint")
	}
	if u.Scheme != "https" {
		return errors.New("push endpoint must use https")
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid push endpoint")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("push endpoint host not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
		return errors.New("push endpoint host not allowed")
	}
	return nil
}

// isPublicIP reports whether ip is a global unicast address. It rejects
// loopback, private, link-local, multicast, unspecified, and CGNAT ranges —
// including cloud metadata addresses such as 169.254.169.254.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// CGNAT 100.64.0.0/10 and the 192.0.0.0/24 protocol range.
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return false
		}
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 0 {
			return false
		}
	}
	return true
}

// NewClient returns an HTTP client for push delivery. The dialer refuses every
// non-public resolved address (covering DNS rebinding), and redirects are not
// followed, so an allowed endpoint cannot bounce the server at an internal
// target (audit F-09).
func NewClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return errors.New("invalid dial address")
			}
			ip := net.ParseIP(host)
			if ip == nil || !isPublicIP(ip) {
				return errors.New("push endpoint resolves to a non-public address")
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("push endpoint redirect refused")
		},
	}
}

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

// DispatcherStore is the storage subset the dispatcher needs.
type DispatcherStore interface {
	GetDevice(ctx context.Context, userID string, deviceID int) (*storage.Device, error)
	UpdatePushEndpoint(ctx context.Context, userID string, deviceID int, endpoint *string) error
}

// Dispatcher sends wakeups and retires endpoints that keep failing.
type Dispatcher struct {
	store       DispatcherStore
	client      *http.Client
	timeout     time.Duration
	maxFailures int

	mu       sync.Mutex
	failures map[string]int
}

// NewDispatcher builds a dispatcher using the SSRF-hardened client.
func NewDispatcher(store DispatcherStore) *Dispatcher {
	return &Dispatcher{
		store:       store,
		client:      NewClient(10 * time.Second),
		timeout:     10 * time.Second,
		maxFailures: 5,
		failures:    make(map[string]int),
	}
}

// Wake looks up the device's registered endpoint and sends a wakeup. Dead
// endpoints are cleared after repeated failures (audit F-09).
func (d *Dispatcher) Wake(userID string, deviceID int) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	dev, err := d.store.GetDevice(ctx, userID, deviceID)
	if err != nil || dev.PushEndpoint == nil || dev.RevokedAt != nil {
		return
	}
	if err := ValidateEndpoint(*dev.PushEndpoint); err != nil {
		slog.Warn("push endpoint rejected; clearing", "error", err)
		d.clear(ctx, userID, deviceID)
		return
	}
	if err := Wake(ctx, d.client, *dev.PushEndpoint); err != nil {
		slog.Debug("push wake failed", "error", err)
		if d.fail(userID, deviceID) >= d.maxFailures {
			d.clear(ctx, userID, deviceID)
		}
		return
	}
	d.reset(userID, deviceID)
}

func deviceKey(userID string, deviceID int) string {
	return userID + ":" + strconv.Itoa(deviceID)
}

func (d *Dispatcher) fail(userID string, deviceID int) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := deviceKey(userID, deviceID)
	d.failures[k]++
	return d.failures[k]
}

func (d *Dispatcher) reset(userID string, deviceID int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.failures, deviceKey(userID, deviceID))
}

func (d *Dispatcher) clear(ctx context.Context, userID string, deviceID int) {
	d.reset(userID, deviceID)
	if err := d.store.UpdatePushEndpoint(ctx, userID, deviceID, nil); err != nil {
		slog.Warn("push endpoint clear failed", "error", err)
	}
}
