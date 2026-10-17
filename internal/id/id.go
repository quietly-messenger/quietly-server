// Package id generates the server-side identifiers: UUIDv4 for accounts and
// monotonic ULIDs for messages (PROTOCOL.md §1, §11).
package id

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// UUIDv4 returns a random RFC 4122 version-4 UUID string.
func UUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ULID is a monotonic ULID generator. Within one process, two calls in the
// same millisecond return strictly increasing values.
type ULID struct {
	mu      sync.Mutex
	lastMS  uint64
	lastRnd [10]byte
	seeded  bool
}

// NewULID returns a monotonic ULID generator.
func NewULID() *ULID { return &ULID{} }

// Next returns the next ULID as a 26-character string.
func (g *ULID) Next() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	ms := uint64(time.Now().UnixMilli())

	var rnd [10]byte
	switch {
	case g.seeded && ms == g.lastMS:
		// Same millisecond: increment the previous random part to stay
		// monotonic; on overflow roll to the next millisecond.
		copy(rnd[:], g.lastRnd[:])
		carry := true
		for i := 9; i >= 0 && carry; i-- {
			rnd[i]++
			carry = rnd[i] == 0
		}
		if carry {
			ms++
		}
	case g.seeded && ms < g.lastMS:
		// Clock moved backwards: keep monotonic by reusing the last millisecond.
		ms = g.lastMS
		copy(rnd[:], g.lastRnd[:])
		for i := 9; i >= 0; i-- {
			rnd[i]++
			if rnd[i] != 0 {
				break
			}
		}
	default:
		_, _ = rand.Read(rnd[:])
	}

	g.seeded = true
	g.lastMS = ms
	copy(g.lastRnd[:], rnd[:])

	var b [16]byte
	// The ULID timestamp is 48 bits. Put ms into the top 48 bits (shifted up
	// 16), then overwrite the low 10 bytes with randomness. Writing the full
	// 64-bit ms would let the low 16 bits of the timestamp collide with the
	// random bytes and break cross-millisecond monotonicity (audit F-05).
	binary.BigEndian.PutUint64(b[:8], ms<<16)
	copy(b[6:], rnd[:])
	return encodeULID(b)
}

// encodeULID encodes a 16-byte (128-bit) value as 26 Crockford base32
// characters, most-significant first.
func encodeULID(b [16]byte) string {
	var out [26]byte
	var acc uint32
	var n uint
	oi := 0
	for i := 0; i < 16; i++ {
		acc = acc<<8 | uint32(b[i])
		n += 8
		for n >= 5 {
			n -= 5
			out[oi] = crockford[(acc>>n)&0x1f]
			oi++
		}
	}
	if n > 0 {
		out[oi] = crockford[(acc<<(5-n))&0x1f]
	}
	return string(out[:])
}
