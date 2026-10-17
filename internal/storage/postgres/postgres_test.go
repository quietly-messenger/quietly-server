// Integration tests for the PostgreSQL Store. They run against a real database
// named by DATABASE_URL and skip when it is unset, so `go test ./...` stays
// green without Postgres. Each test gets its own schema (so tests can run in
// parallel against one database) and the schema is built by applying the real
// migration files, which also covers the migrations themselves.
package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quietly-messenger/quietly-server/internal/storage"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DATABASE_URL: %v", err)
	}
	cfg.MaxConns = 16

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "quietly_test_" + hex.EncodeToString(suffix[:])
	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	admin, err := pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		t.Fatalf("connect to database: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })

	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	})

	applyMigrations(t, admin)

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return New(pool)
}

// applyMigrations runs the real migration files, so the schema under test is
// exactly what deployments get. The simple-query protocol is required because
// each file holds several statements.
func applyMigrations(t *testing.T, admin *pgx.Conn) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no migration files found")
	}
	sort.Strings(files)
	for _, f := range files {
		sqlBytes, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		mrr := admin.PgConn().Exec(context.Background(), string(sqlBytes))
		if _, err := mrr.ReadAll(); err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(f), err)
		}
	}
}

func rb(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// testDevice builds a device record with fresh random key material. The
// storage layer never validates crypto, so bytes are enough.
func testDevice(t *testing.T) *storage.Device {
	t.Helper()
	token := rb(t, 32)
	hash := sha256.Sum256(token)
	return &storage.Device{
		IdentityKeyDH:     rb(t, 32),
		IdentityKeySig:    rb(t, 32),
		IdentityBinding:   rb(t, 64),
		SignedPreKeyID:    1,
		SignedPreKey:      rb(t, 32),
		SignedPreKeySig:   rb(t, 64),
		DeliveryToken:     token,
		DeliveryTokenHash: hash[:],
	}
}

func mustAccount(t *testing.T, st *Store, username string) (*storage.User, *storage.Device) {
	t.Helper()
	u, d, err := st.CreateAccountWithDevice(context.Background(), username, testDevice(t), nil)
	if err != nil {
		t.Fatalf("create account %q: %v", username, err)
	}
	return u, d
}

func countRows(t *testing.T, st *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	return n
}

// TestCreateAccountWithDeviceIsAtomic covers audit F-10 at the SQL layer: a
// failure in any later statement must roll back the account row, the device
// row, and the prekey batch together.
func TestCreateAccountWithDeviceIsAtomic(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, d, err := st.CreateAccountWithDevice(ctx, "alice", testDevice(t),
		[]storage.OneTimePreKey{{ID: 1, PublicKey: rb(t, 32)}})
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if u.ID == "" || d.ID != 1 || d.UserID != u.ID {
		t.Fatalf("returned user/device not wired up: user=%+v device=%+v", u, d)
	}

	// Duplicate username: conflict on the first insert.
	if _, _, err := st.CreateAccountWithDevice(ctx, "alice", testDevice(t), nil); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("duplicate username error = %v, want ErrConflict", err)
	}
	if n := countRows(t, st, `SELECT count(*) FROM users WHERE username = 'alice'`); n != 1 {
		t.Fatalf("users named alice = %d, want 1", n)
	}
	if n := countRows(t, st, `SELECT count(*) FROM devices WHERE user_id = $1`, u.ID); n != 1 {
		t.Fatalf("devices for alice = %d, want 1", n)
	}

	// Duplicate prekey id inside the batch: the failure happens after the user
	// and device rows were inserted, so the whole transaction must roll back.
	_, _, err = st.CreateAccountWithDevice(ctx, "bob", testDevice(t),
		[]storage.OneTimePreKey{{ID: 5, PublicKey: rb(t, 32)}, {ID: 5, PublicKey: rb(t, 32)}})
	if !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("duplicate prekey error = %v, want ErrConflict", err)
	}
	if n := countRows(t, st, `SELECT count(*) FROM users WHERE username = 'bob'`); n != 0 {
		t.Fatalf("rolled-back user survived: count = %d", n)
	}
	if n := countRows(t, st, `SELECT count(*) FROM devices`); n != 1 {
		t.Fatalf("devices after rollback = %d, want only alice's", n)
	}

	// The username is free again after the rollback.
	if _, d2, err := st.CreateAccountWithDevice(ctx, "bob", testDevice(t),
		[]storage.OneTimePreKey{{ID: 5, PublicKey: rb(t, 32)}}); err != nil {
		t.Fatalf("retry bob after rollback: %v", err)
	} else if d2.ID != 1 {
		t.Fatalf("retry bob device id = %d, want 1", d2.ID)
	}
}

// TestCreateDeviceConcurrentAssignsDistinctIDs exercises the user-row lock
// that makes `MAX(id)+1` safe under concurrent device registration.
func TestCreateDeviceConcurrentAssignsDistinctIDs(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	u, _ := mustAccount(t, st, "carol")

	const extra = 4
	devices := make([]*storage.Device, extra)
	for i := range devices {
		devices[i] = testDevice(t)
		devices[i].UserID = u.ID
	}
	var wg sync.WaitGroup
	ids := make([]int, extra)
	errs := make([]error, extra)
	for i := 0; i < extra; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			created, err := st.CreateDevice(ctx, devices[i], nil)
			if err != nil {
				errs[i] = err
				return
			}
			ids[i] = created.ID
		}()
	}
	wg.Wait()

	seen := map[int]bool{1: true}
	for i := 0; i < extra; i++ {
		if errs[i] != nil {
			t.Fatalf("concurrent CreateDevice: %v", errs[i])
		}
		if seen[ids[i]] {
			t.Fatalf("duplicate device id %d assigned", ids[i])
		}
		seen[ids[i]] = true
	}
	if len(seen) != extra+1 {
		t.Fatalf("distinct device ids = %d, want %d", len(seen), extra+1)
	}
	if n, err := st.CountActiveDevices(ctx, u.ID); err != nil || n != extra+1 {
		t.Fatalf("CountActiveDevices = %d (err %v), want %d", n, err, extra+1)
	}
	listed, err := st.ListDevices(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range listed {
		if d.ID != i+1 {
			t.Fatalf("ListDevices[%d].ID = %d, want %d (not sorted/assigned densely)", i, d.ID, i+1)
		}
	}
}

// TestAddOneTimePreKeysRollsBackOnConflict covers the F-17 transactional fix:
// a conflicting batch must land none of its keys, not the subset before the
// conflict.
func TestAddOneTimePreKeysRollsBackOnConflict(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	u, _ := mustAccount(t, st, "dana")

	if err := st.AddOneTimePreKeys(ctx, u.ID, 1, []storage.OneTimePreKey{
		{ID: 10, PublicKey: rb(t, 32)},
		{ID: 11, PublicKey: rb(t, 32)},
	}); err != nil {
		t.Fatalf("first batch: %v", err)
	}

	err := st.AddOneTimePreKeys(ctx, u.ID, 1, []storage.OneTimePreKey{
		{ID: 12, PublicKey: rb(t, 32)},
		{ID: 11, PublicKey: rb(t, 32)}, // conflicts with the first batch
	})
	if !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("conflicting batch error = %v, want ErrConflict", err)
	}
	if n := countRows(t, st, `SELECT count(*) FROM one_time_prekeys WHERE device_user_id = $1 AND device_id = 1`, u.ID); n != 2 {
		t.Fatalf("stored prekeys = %d, want 2 (key 12 leaked from the failed batch)", n)
	}

	// The original two are still served, in id order, with no half-batch gap.
	for want := uint32(10); want <= 11; want++ {
		p, err := st.TakeOneTimePreKey(ctx, u.ID, 1)
		if err != nil {
			t.Fatalf("take %d: %v", want, err)
		}
		if p.ID != want {
			t.Fatalf("took prekey %d, want %d", p.ID, want)
		}
	}
	if _, err := st.TakeOneTimePreKey(ctx, u.ID, 1); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("take from empty pool error = %v, want ErrNotFound", err)
	}
}

// TestTakeOneTimePreKeyConcurrent exercises the FOR UPDATE SKIP LOCKED query:
// concurrent fetches must never hand the same key to two requesters.
func TestTakeOneTimePreKeyConcurrent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	u, _ := mustAccount(t, st, "erin")

	const total, workers = 16, 8
	prekeys := make([]storage.OneTimePreKey, total)
	for i := range prekeys {
		prekeys[i] = storage.OneTimePreKey{ID: uint32(i + 1), PublicKey: rb(t, 32)}
	}
	if err := st.AddOneTimePreKeys(ctx, u.ID, 1, prekeys); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	taken := map[uint32]bool{}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := st.TakeOneTimePreKey(ctx, u.ID, 1)
			if err != nil {
				t.Errorf("concurrent take: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if taken[p.ID] {
				t.Errorf("prekey %d handed out twice", p.ID)
			}
			taken[p.ID] = true
		}()
	}
	wg.Wait()
	if len(taken) != workers {
		t.Fatalf("concurrent takes produced %d distinct keys, want %d", len(taken), workers)
	}

	// Drain the rest sequentially: every remaining key must be a fresh one.
	for i := 0; i < total-workers; i++ {
		p, err := st.TakeOneTimePreKey(ctx, u.ID, 1)
		if err != nil {
			t.Fatalf("drain take %d: %v", i, err)
		}
		if taken[p.ID] {
			t.Fatalf("prekey %d handed out twice (across concurrent + sequential)", p.ID)
		}
		taken[p.ID] = true
	}
	if len(taken) != total {
		t.Fatalf("distinct keys = %d, want %d", len(taken), total)
	}
	if n, err := st.CountAvailablePreKeys(ctx, u.ID, 1); err != nil || n != 0 {
		t.Fatalf("CountAvailablePreKeys = %d (err %v), want 0", n, err)
	}
}

// TestPreKeyIssuanceRoundTrip covers the §7.2.1 idempotency table: recording
// is an upsert, so a re-fetch window refresh replaces the stored key.
func TestPreKeyIssuanceRoundTrip(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	req, _ := mustAccount(t, st, "frank")
	target, _ := mustAccount(t, st, "gina")

	first := storage.OneTimePreKey{ID: 7, PublicKey: rb(t, 32)}
	if err := st.RecordPreKeyIssuance(ctx, req.ID, 1, target.ID, 1, first); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, at, err := st.GetPreKeyIssuance(ctx, req.ID, 1, target.ID, 1)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != 7 || string(got.PublicKey) != string(first.PublicKey) {
		t.Fatalf("issuance round-trip mismatch: %+v", got)
	}
	if time.Since(at) > time.Minute {
		t.Fatalf("issued_at looks wrong: %v", at)
	}

	second := storage.OneTimePreKey{ID: 8, PublicKey: rb(t, 32)}
	time.Sleep(10 * time.Millisecond) // make issued_at observably newer
	if err := st.RecordPreKeyIssuance(ctx, req.ID, 1, target.ID, 1, second); err != nil {
		t.Fatalf("re-record: %v", err)
	}
	got, at2, err := st.GetPreKeyIssuance(ctx, req.ID, 1, target.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 8 {
		t.Fatalf("re-record did not replace the key: got id %d", got.ID)
	}
	if !at2.After(at) {
		t.Fatalf("issued_at did not advance on re-record: %v then %v", at, at2)
	}

	// The reverse direction is a different pair and must not appear.
	if _, _, err := st.GetPreKeyIssuance(ctx, target.ID, 1, req.ID, 1); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("reverse pair error = %v, want ErrNotFound", err)
	}
}

// TestPrunePreKeyIssuances covers the F-02 residual at the SQL layer: records
// past the §7.2.1 window are deleted, fresh ones survive, and the count says
// how many rows went away.
func TestPrunePreKeyIssuances(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	req, _ := mustAccount(t, st, "iris")
	old, _ := mustAccount(t, st, "jack")
	fresh, _ := mustAccount(t, st, "kate")

	oldKey := storage.OneTimePreKey{ID: 1, PublicKey: rb(t, 32)}
	freshKey := storage.OneTimePreKey{ID: 2, PublicKey: rb(t, 32)}
	if err := st.RecordPreKeyIssuance(ctx, req.ID, 1, old.ID, 1, oldKey); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordPreKeyIssuance(ctx, req.ID, 1, fresh.ID, 1, freshKey); err != nil {
		t.Fatal(err)
	}

	// Backdate the first record past the window.
	if _, err := st.pool.Exec(ctx,
		`UPDATE prekey_issuances SET issued_at = now() - interval '25 hours' WHERE target_user_id = $1`,
		old.ID); err != nil {
		t.Fatal(err)
	}

	n, err := st.PrunePreKeyIssuances(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}
	if _, _, err := st.GetPreKeyIssuance(ctx, req.ID, 1, old.ID, 1); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired issuance error = %v, want ErrNotFound", err)
	}
	got, _, err := st.GetPreKeyIssuance(ctx, req.ID, 1, fresh.ID, 1)
	if err != nil {
		t.Fatalf("fresh issuance: %v", err)
	}
	if got.ID != freshKey.ID {
		t.Fatalf("fresh issuance id = %d, want %d", got.ID, freshKey.ID)
	}

	// A second pass has nothing left to delete.
	if n, err := st.PrunePreKeyIssuances(ctx, time.Now().Add(-24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("second prune = %d, %v; want 0, nil", n, err)
	}
}

// TestMessageLifecycle covers enqueue/list/ack/expiry semantics on the real
// queries, including ULID ordering for messages sharing a timestamp.
func TestMessageLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	u, _ := mustAccount(t, st, "hana")

	d2 := testDevice(t)
	d2.UserID = u.ID
	if _, err := st.CreateDevice(ctx, d2, nil); err != nil {
		t.Fatal(err)
	}

	ts := time.Now().UTC().Truncate(time.Millisecond)
	enqueue := func(deviceID int, sealed string, serverTS time.Time, ttl time.Duration) *storage.Message {
		t.Helper()
		m := &storage.Message{
			RecipientUserID:   u.ID,
			RecipientDeviceID: deviceID,
			Sealed:            []byte(sealed),
			ServerTS:          serverTS,
			TTLExpiresAt:      serverTS.Add(ttl),
		}
		if err := st.EnqueueMessage(ctx, m); err != nil {
			t.Fatalf("enqueue %q: %v", sealed, err)
		}
		if m.ID == "" {
			t.Fatal("enqueue did not assign an id")
		}
		return m
	}

	m1 := enqueue(1, "a", ts, time.Hour)
	m2 := enqueue(1, "b", ts, time.Hour) // same timestamp: order must fall back to the ULID
	m3 := enqueue(1, "c", ts.Add(time.Second), time.Hour)
	expired := enqueue(1, "old", ts, -time.Minute)
	other := enqueue(2, "x", ts, time.Hour)

	if m1.ID == m2.ID || m2.ID == m3.ID {
		t.Fatalf("ids not unique: %q %q %q", m1.ID, m2.ID, m3.ID)
	}

	msgs, err := st.ListMessages(ctx, u.ID, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].ID != m1.ID || msgs[1].ID != m2.ID {
		t.Fatalf("limit 2 returned %v, want [%s %s]", ids(msgs), m1.ID, m2.ID)
	}
	msgs, err = st.ListMessages(ctx, u.ID, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 4 {
		t.Fatalf("full list returned %d messages, want 4", len(msgs))
	}
	if msgs[2].ID != expired.ID || msgs[3].ID != m3.ID {
		t.Fatalf("ordering wrong: %v", ids(msgs))
	}

	// Ack: device 2 may not ack device 1's message; device 1 may, once.
	if err := st.AckMessage(ctx, u.ID, 2, m1.ID); !errors.Is(err, storage.ErrForbidden) {
		t.Fatalf("foreign ack error = %v, want ErrForbidden", err)
	}
	if err := st.AckMessage(ctx, u.ID, 1, m1.ID); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if err := st.AckMessage(ctx, u.ID, 1, m1.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("double ack error = %v, want ErrNotFound", err)
	}
	if err := st.AckMessage(ctx, u.ID, 1, "01ARZ3NDEKTSV4RRFFQ69G5FAV"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown id ack error = %v, want ErrNotFound", err)
	}

	// Expiry deletes only messages past their TTL.
	n, err := st.DeleteExpiredMessages(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("DeleteExpiredMessages = %d, want 1", n)
	}
	msgs, err = st.ListMessages(ctx, u.ID, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("after expiry: %v, want [m2 m3]", ids(msgs))
	}

	// The other device's queue is untouched by all of the above.
	msgs, err = st.ListMessages(ctx, u.ID, 2, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].ID != other.ID {
		t.Fatalf("device 2 queue = %v, want [%s]", ids(msgs), other.ID)
	}

	// Enqueueing for a nonexistent recipient device must fail (FK), not
	// silently queue an undeliverable message.
	bad := &storage.Message{RecipientUserID: u.ID, RecipientDeviceID: 99, Sealed: []byte("z"),
		ServerTS: ts, TTLExpiresAt: ts.Add(time.Hour)}
	if err := st.EnqueueMessage(ctx, bad); err == nil {
		t.Fatal("enqueue for unknown device succeeded")
	}
}

func ids(msgs []storage.Message) []string {
	out := make([]string, len(msgs))
	for i, m := range msgs {
		out[i] = m.ID
	}
	return out
}

// TestRevokeDevicePurgesQueuedMessages covers F-11 on the real SQL path: the
// revocation transaction marks the device revoked and deletes its queue.
func TestRevokeDevicePurgesQueuedMessages(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	u, _ := mustAccount(t, st, "ivan")

	d2 := testDevice(t)
	d2.UserID = u.ID
	if _, err := st.CreateDevice(ctx, d2, nil); err != nil {
		t.Fatal(err)
	}

	ts := time.Now().UTC()
	for _, dev := range []int{1, 2} {
		if err := st.EnqueueMessage(ctx, &storage.Message{
			RecipientUserID: u.ID, RecipientDeviceID: dev,
			Sealed: []byte("sealed"), ServerTS: ts, TTLExpiresAt: ts.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := st.RevokeDevice(ctx, u.ID, 1); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := st.RevokeDevice(ctx, u.ID, 1); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("double revoke error = %v, want ErrNotFound", err)
	}

	dev, err := st.GetDevice(ctx, u.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if dev.RevokedAt == nil {
		t.Fatal("revoked_at not set")
	}
	if n := countRows(t, st, `SELECT count(*) FROM messages WHERE recipient_user_id = $1 AND recipient_device_id = 1`, u.ID); n != 0 {
		t.Fatalf("revoked device still has %d queued messages", n)
	}
	msgs, err := st.ListMessages(ctx, u.ID, 2, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("device 2 queue was disturbed: %v", ids(msgs))
	}
	if n, err := st.CountActiveDevices(ctx, u.ID); err != nil || n != 1 {
		t.Fatalf("CountActiveDevices = %d (err %v), want 1", n, err)
	}

	if err := st.DeleteMessagesForDevice(ctx, u.ID, 2); err != nil {
		t.Fatal(err)
	}
	msgs, err = st.ListMessages(ctx, u.ID, 2, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("DeleteMessagesForDevice left %v", ids(msgs))
	}
}

// TestUpdatePathsAndNotFound checks the mutation paths' no-op guards and the
// mapping from pgx errors to storage sentinels.
func TestUpdatePathsAndNotFound(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	u, _ := mustAccount(t, st, "jack")
	created, err := st.GetDevice(ctx, u.ID, 1)
	if err != nil {
		t.Fatal(err)
	}

	const missingUser = "00000000-0000-4000-8000-000000000000"

	if _, err := st.GetUser(ctx, missingUser); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetUser: %v", err)
	}
	if _, err := st.GetUserByUsername(ctx, "nobody"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if _, err := st.GetDevice(ctx, u.ID, 9); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetDevice: %v", err)
	}
	if err := st.UpdateSignedPreKey(ctx, u.ID, 9, 2, rb(t, 32), rb(t, 64)); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("UpdateSignedPreKey on missing device: %v", err)
	}
	if err := st.UpdateDeliveryToken(ctx, u.ID, 9, rb(t, 32), rb(t, 32)); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("UpdateDeliveryToken on missing device: %v", err)
	}
	if err := st.UpdatePushEndpoint(ctx, u.ID, 9, nil); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("UpdatePushEndpoint on missing device: %v", err)
	}

	// Signed-prekey rotation records the new key and refreshes the timestamp.
	before := created.SignedPreKeyRotatedAt
	spk, sig := rb(t, 32), rb(t, 64)
	if err := st.UpdateSignedPreKey(ctx, u.ID, 1, 2, spk, sig); err != nil {
		t.Fatalf("rotate spk: %v", err)
	}
	got, err := st.GetDevice(ctx, u.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.SignedPreKeyID != 2 || string(got.SignedPreKey) != string(spk) || string(got.SignedPreKeySig) != string(sig) {
		t.Fatalf("rotation not persisted: %+v", got)
	}
	if got.SignedPreKeyRotatedAt.Before(before) {
		t.Fatalf("rotated_at went backwards: %v -> %v", before, got.SignedPreKeyRotatedAt)
	}

	// Push endpoint set/clear round trip, including NULL handling.
	endpoint := "https://push.example/topic"
	if err := st.UpdatePushEndpoint(ctx, u.ID, 1, &endpoint); err != nil {
		t.Fatal(err)
	}
	if got, err := st.GetDevice(ctx, u.ID, 1); err != nil || got.PushEndpoint == nil || *got.PushEndpoint != endpoint {
		t.Fatalf("push endpoint not persisted: %+v (err %v)", got, err)
	}
	if err := st.UpdatePushEndpoint(ctx, u.ID, 1, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := st.GetDevice(ctx, u.ID, 1); err != nil || got.PushEndpoint != nil {
		t.Fatalf("push endpoint not cleared: %+v (err %v)", got, err)
	}

	// Username uniqueness at the CreateUser level too.
	if _, err := st.CreateUser(ctx, "jack"); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("duplicate CreateUser: %v", err)
	}
}
