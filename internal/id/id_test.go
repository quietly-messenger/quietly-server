package id

import (
	"strings"
	"testing"
)

func TestUUIDv4Format(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		u, err := UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		if len(u) != 36 {
			t.Fatalf("uuid length = %d", len(u))
		}
		if u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' {
			t.Fatalf("bad hyphen placement in %q", u)
		}
		if u[14] != '4' {
			t.Fatalf("not version 4: %q", u)
		}
		if seen[u] {
			t.Fatalf("duplicate uuid %q", u)
		}
		seen[u] = true
	}
}

func TestULIDFormatAndMonotonic(t *testing.T) {
	g := NewULID()
	prev := ""
	for i := 0; i < 2000; i++ {
		u := g.Next()
		if len(u) != 26 {
			t.Fatalf("ulid length = %d", len(u))
		}
		for _, c := range u {
			if !strings.ContainsRune(crockford, c) {
				t.Fatalf("invalid ulid character %q in %q", c, u)
			}
		}
		if prev != "" && u <= prev {
			t.Fatalf("ulid not monotonic: %q <= %q", u, prev)
		}
		prev = u
	}
}
