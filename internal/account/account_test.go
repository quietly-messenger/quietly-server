package account

import (
	"strings"
	"testing"
)

func TestValidUsername(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		{"alice", true},
		{"bob_42", true},
		{"a1_b2_c3", true},
		{"abc", true},
		{strings.Repeat("a", 32), true},
		{strings.Repeat("a", 33), false},
		{"ab", false},
		{"Alice", false},
		{"with space", false},
		{"with-dash", false},
		{"with.dot", false},
		{"", false},
	}
	for _, c := range cases {
		if got := validUsername(c.name); got != c.valid {
			t.Errorf("validUsername(%q) = %v, want %v", c.name, got, c.valid)
		}
	}
}
