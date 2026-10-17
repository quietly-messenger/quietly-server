package http

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quietly-messenger/quietly-server/internal/config"
)

func mustNets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// TestClientIPKeying pins audit F-23: X-Forwarded-For may only steer the
// rate-limit key when the direct peer is a configured trusted proxy, and then
// only the rightmost untrusted hop counts — anything left of it was supplied
// by the client itself.
func TestClientIPKeying(t *testing.T) {
	s := &Server{trustedProxies: mustNets(t, "10.0.0.0/8", "::1/128")}

	tests := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		{"untrusted peer, spoofed header ignored", "203.0.113.7:5555", "9.9.9.9", "203.0.113.7"},
		{"untrusted peer, no header", "203.0.113.7:5555", "", "203.0.113.7"},
		{"trusted peer, no header", "10.1.2.3:5555", "", "10.1.2.3"},
		{"trusted peer, single hop", "10.1.2.3:5555", "9.9.9.9", "9.9.9.9"},
		{"trusted peer, rightmost hop trusted", "10.1.2.3:5555", "6.6.6.6, 10.4.4.4", "6.6.6.6"},
		{"attacker-supplied prefix ignored", "10.1.2.3:5555", "evil, 9.9.9.9, 10.4.4.4", "9.9.9.9"},
		{"malformed hop falls back to peer", "10.1.2.3:5555", "9.9.9.9, evil", "10.1.2.3"},
		{"all hops trusted falls back to peer", "10.1.2.3:5555", "10.4.4.4, 10.5.5.5", "10.1.2.3"},
		{"ipv6 trusted peer", "[::1]:5555", "2001:db8::1", "2001:db8::1"},
		{"whitespace trimmed", "10.1.2.3:5555", "  9.9.9.9 , 10.4.4.4  ", "9.9.9.9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/accounts/pow-params", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := s.clientIP(r); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRateLimitXFFKeying is the permanent regression for the F-23 bypass
// repro: a client that uniquifies X-Forwarded-For must not receive a fresh
// bucket per request unless it connects through a configured proxy.
func TestRateLimitXFFKeying(t *testing.T) {
	limited := func(t *testing.T, trusted []*net.IPNet) *Server {
		t.Helper()
		limits := config.DefaultLimits()
		limits.RequestsPerMinute = 2 // burst of 2: the third request must 429
		return NewServer(nil, nil, nil, limits, nil, trusted)
	}
	run := func(s *Server, remote string, xff func(i int) string) []int {
		h := s.rateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		var codes []int
		for i := 0; i < 3; i++ {
			r := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			r.RemoteAddr = remote
			r.Header.Set("X-Forwarded-For", xff(i))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			codes = append(codes, w.Code)
		}
		return codes
	}
	want := func(t *testing.T, got []int, last int) {
		t.Helper()
		for i, code := range got {
			expect := http.StatusOK
			if i == len(got)-1 {
				expect = last
			}
			if code != expect {
				t.Fatalf("status codes = %v, want the last one to be %d", got, last)
			}
		}
	}

	t.Run("spoofed XFF ignored without trusted proxies", func(t *testing.T) {
		s := limited(t, nil)
		got := run(s, "203.0.113.9:4444", func(i int) string {
			return fmt.Sprintf("9.9.9.%d", i)
		})
		want(t, got, http.StatusTooManyRequests)
	})

	t.Run("trusted proxy keys on the forwarded client", func(t *testing.T) {
		s := limited(t, mustNets(t, "10.0.0.0/8"))
		got := run(s, "10.1.2.3:4444", func(i int) string {
			return fmt.Sprintf("9.9.9.%d", i)
		})
		want(t, got, http.StatusOK)
	})

	t.Run("trusted proxy throttles a repeated forwarded client", func(t *testing.T) {
		s := limited(t, mustNets(t, "10.0.0.0/8"))
		got := run(s, "10.1.2.3:4444", func(int) string { return "9.9.9.9" })
		want(t, got, http.StatusTooManyRequests)
	})
}
