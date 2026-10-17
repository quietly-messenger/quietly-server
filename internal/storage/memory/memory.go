// Package memory is an in-memory storage.Store used by tests and for local
// development runs without Postgres. It mirrors the postgres implementation's
// observable semantics, including atomic account creation, prekey consumption,
// ack idempotency, and message purge on revocation.
package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/id"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

type deviceKey struct {
	userID string
	id     int
}

type issuanceKey struct {
	requesterUserID   string
	requesterDeviceID int
	targetUserID      string
	targetDeviceID    int
}

type prekeyRecord struct {
	prekey storage.OneTimePreKey
	used   bool
}

type issuance struct {
	prekey   storage.OneTimePreKey
	issuedAt time.Time
}

// Store is a mutex-guarded in-memory store.
type Store struct {
	mu sync.RWMutex

	now  func() time.Time
	ulid *id.ULID

	users     map[string]*storage.User
	usernames map[string]string
	devices   map[deviceKey]*storage.Device
	prekeys   map[deviceKey]map[uint32]*prekeyRecord
	issuances map[issuanceKey]issuance
	messages  map[string]*storage.Message
}

var _ storage.Store = (*Store)(nil)

// New builds an empty store.
func New() *Store {
	return &Store{
		now:       time.Now,
		ulid:      id.NewULID(),
		users:     make(map[string]*storage.User),
		usernames: make(map[string]string),
		devices:   make(map[deviceKey]*storage.Device),
		prekeys:   make(map[deviceKey]map[uint32]*prekeyRecord),
		issuances: make(map[issuanceKey]issuance),
		messages:  make(map[string]*storage.Message),
	}
}

// SetNow overrides the store's clock (tests only).
func (s *Store) SetNow(fn func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = fn
}

func (s *Store) clock() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.now()
}

func cloneDevice(d *storage.Device) *storage.Device {
	cp := *d
	return &cp
}

func cloneMessage(m *storage.Message) *storage.Message {
	cp := *m
	cp.Sealed = append([]byte(nil), m.Sealed...)
	return &cp
}

func (s *Store) deviceKeyLocked(userID string, deviceID int) deviceKey {
	return deviceKey{userID: userID, id: deviceID}
}

// --- Users ---

func (s *Store) CreateUser(_ context.Context, username string) (*storage.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.usernames[username]; ok {
		return nil, storage.ErrConflict
	}
	uid, err := id.UUIDv4()
	if err != nil {
		return nil, err
	}
	u := &storage.User{ID: uid, Username: username, CreatedAt: s.now()}
	s.users[uid] = u
	s.usernames[username] = uid
	cp := *u
	return &cp, nil
}

func (s *Store) CreateAccountWithDevice(_ context.Context, username string, d *storage.Device, prekeys []storage.OneTimePreKey) (*storage.User, *storage.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.usernames[username]; ok {
		return nil, nil, storage.ErrConflict
	}
	seen := make(map[uint32]bool, len(prekeys))
	for _, p := range prekeys {
		if seen[p.ID] {
			return nil, nil, storage.ErrConflict
		}
		seen[p.ID] = true
	}
	uid, err := id.UUIDv4()
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	u := &storage.User{ID: uid, Username: username, CreatedAt: now}
	dev := cloneDevice(d)
	dev.ID = 1
	dev.UserID = uid
	dev.CreatedAt = now
	dev.SignedPreKeyRotatedAt = now

	s.users[uid] = u
	s.usernames[username] = uid
	s.devices[deviceKey{userID: uid, id: 1}] = dev
	recs := make(map[uint32]*prekeyRecord, len(prekeys))
	for _, p := range prekeys {
		recs[p.ID] = &prekeyRecord{prekey: p}
	}
	s.prekeys[deviceKey{userID: uid, id: 1}] = recs

	uc := *u
	return &uc, cloneDevice(dev), nil
}

func (s *Store) GetUserByUsername(_ context.Context, username string) (*storage.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.usernames[username]
	if !ok {
		return nil, storage.ErrNotFound
	}
	u := *s.users[uid]
	return &u, nil
}

func (s *Store) GetUser(_ context.Context, userID string) (*storage.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[userID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

// --- Devices ---

func (s *Store) CreateDevice(_ context.Context, d *storage.Device, prekeys []storage.OneTimePreKey) (*storage.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[d.UserID]; !ok {
		return nil, storage.ErrNotFound
	}
	next := 1
	for k := range s.devices {
		if k.userID == d.UserID && k.id >= next {
			next = k.id + 1
		}
	}
	seen := make(map[uint32]bool, len(prekeys))
	for _, p := range prekeys {
		if seen[p.ID] {
			return nil, storage.ErrConflict
		}
		seen[p.ID] = true
	}
	now := s.now()
	dev := cloneDevice(d)
	dev.ID = next
	dev.CreatedAt = now
	dev.SignedPreKeyRotatedAt = now
	s.devices[deviceKey{userID: d.UserID, id: next}] = dev
	recs := make(map[uint32]*prekeyRecord, len(prekeys))
	for _, p := range prekeys {
		recs[p.ID] = &prekeyRecord{prekey: p}
	}
	s.prekeys[deviceKey{userID: d.UserID, id: next}] = recs
	return cloneDevice(dev), nil
}

func (s *Store) GetDevice(_ context.Context, userID string, deviceID int) (*storage.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[deviceKey{userID: userID, id: deviceID}]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cloneDevice(d), nil
}

func (s *Store) ListDevices(_ context.Context, userID string) ([]storage.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []storage.Device
	for k, d := range s.devices {
		if k.userID == userID {
			out = append(out, *cloneDevice(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) CountActiveDevices(_ context.Context, userID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for k, d := range s.devices {
		if k.userID == userID && d.RevokedAt == nil {
			n++
		}
	}
	return n, nil
}

func (s *Store) RevokeDevice(_ context.Context, userID string, deviceID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := deviceKey{userID: userID, id: deviceID}
	d, ok := s.devices[k]
	if !ok || d.RevokedAt != nil {
		return storage.ErrNotFound
	}
	now := s.now()
	d.RevokedAt = &now
	// §2.2: revocation deletes the device's queued messages (audit F-11).
	for mid, m := range s.messages {
		if m.RecipientUserID == userID && m.RecipientDeviceID == deviceID {
			delete(s.messages, mid)
		}
	}
	return nil
}

func (s *Store) UpdateSignedPreKey(_ context.Context, userID string, deviceID int, spkID uint32, spk, sig []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceKey{userID: userID, id: deviceID}]
	if !ok {
		return storage.ErrNotFound
	}
	d.SignedPreKeyID = spkID
	d.SignedPreKey = append([]byte(nil), spk...)
	d.SignedPreKeySig = append([]byte(nil), sig...)
	d.SignedPreKeyRotatedAt = s.now()
	return nil
}

func (s *Store) UpdateDeliveryToken(_ context.Context, userID string, deviceID int, token, tokenHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceKey{userID: userID, id: deviceID}]
	if !ok {
		return storage.ErrNotFound
	}
	d.DeliveryToken = append([]byte(nil), token...)
	d.DeliveryTokenHash = append([]byte(nil), tokenHash...)
	return nil
}

func (s *Store) UpdatePushEndpoint(_ context.Context, userID string, deviceID int, endpoint *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceKey{userID: userID, id: deviceID}]
	if !ok {
		return storage.ErrNotFound
	}
	if endpoint == nil {
		d.PushEndpoint = nil
	} else {
		cp := *endpoint
		d.PushEndpoint = &cp
	}
	return nil
}

// --- One-time prekeys ---

func (s *Store) AddOneTimePreKeys(_ context.Context, userID string, deviceID int, prekeys []storage.OneTimePreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[deviceKey{userID: userID, id: deviceID}]; !ok {
		return storage.ErrNotFound
	}
	k := deviceKey{userID: userID, id: deviceID}
	recs, ok := s.prekeys[k]
	if !ok {
		recs = make(map[uint32]*prekeyRecord)
		s.prekeys[k] = recs
	}
	for _, p := range prekeys {
		if _, exists := recs[p.ID]; exists {
			return storage.ErrConflict
		}
	}
	for _, p := range prekeys {
		recs[p.ID] = &prekeyRecord{prekey: p}
	}
	return nil
}

func (s *Store) TakeOneTimePreKey(_ context.Context, userID string, deviceID int) (*storage.OneTimePreKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs := s.prekeys[deviceKey{userID: userID, id: deviceID}]
	var best *prekeyRecord
	var bestID uint32
	for pid, rec := range recs {
		if rec.used {
			continue
		}
		if best == nil || pid < bestID {
			best, bestID = rec, pid
		}
	}
	if best == nil {
		return nil, storage.ErrNotFound
	}
	best.used = true
	cp := best.prekey
	return &cp, nil
}

func (s *Store) CountAvailablePreKeys(_ context.Context, userID string, deviceID int) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, rec := range s.prekeys[deviceKey{userID: userID, id: deviceID}] {
		if !rec.used {
			n++
		}
	}
	return n, nil
}

func (s *Store) GetPreKeyIssuance(_ context.Context, requesterUserID string, requesterDeviceID int, targetUserID string, targetDeviceID int) (*storage.OneTimePreKey, time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k := issuanceKey{requesterUserID, requesterDeviceID, targetUserID, targetDeviceID}
	iss, ok := s.issuances[k]
	if !ok {
		return nil, time.Time{}, storage.ErrNotFound
	}
	p := iss.prekey
	return &p, iss.issuedAt, nil
}

func (s *Store) RecordPreKeyIssuance(_ context.Context, requesterUserID string, requesterDeviceID int, targetUserID string, targetDeviceID int, prekey storage.OneTimePreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := issuanceKey{requesterUserID, requesterDeviceID, targetUserID, targetDeviceID}
	s.issuances[k] = issuance{prekey: prekey, issuedAt: s.now()}
	return nil
}

func (s *Store) PrunePreKeyIssuances(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, iss := range s.issuances {
		if iss.issuedAt.Before(before) {
			delete(s.issuances, k)
			n++
		}
	}
	return n, nil
}

// --- Messages ---

func (s *Store) EnqueueMessage(_ context.Context, m *storage.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.ID == "" {
		m.ID = s.ulid.Next()
	}
	if _, ok := s.devices[deviceKey{userID: m.RecipientUserID, id: m.RecipientDeviceID}]; !ok {
		return fmt.Errorf("recipient device does not exist")
	}
	if m.NotBefore.IsZero() {
		m.NotBefore = m.ServerTS
	}
	s.messages[m.ID] = cloneMessage(m)
	return nil
}

func (s *Store) ListMessages(_ context.Context, userID string, deviceID int, now time.Time, limit int) ([]storage.Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []storage.Message
	for _, m := range s.messages {
		if m.RecipientUserID == userID && m.RecipientDeviceID == deviceID && !m.NotBefore.After(now) {
			out = append(out, *cloneMessage(m))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServerTS.Equal(out[j].ServerTS) {
			return out[i].ID < out[j].ID
		}
		return out[i].ServerTS.Before(out[j].ServerTS)
	})
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// PendingMessages returns future-due messages ordered by release time
// (TASK-001 B).
func (s *Store) PendingMessages(_ context.Context, now time.Time, limit int) ([]storage.Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []storage.Message
	for _, m := range s.messages {
		if m.NotBefore.After(now) {
			out = append(out, *cloneMessage(m))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NotBefore.Equal(out[j].NotBefore) {
			return out[i].ID < out[j].ID
		}
		return out[i].NotBefore.Before(out[j].NotBefore)
	})
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) AckMessage(_ context.Context, userID string, deviceID int, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.messages[id]
	if !ok {
		return storage.ErrNotFound
	}
	if m.RecipientUserID != userID || m.RecipientDeviceID != deviceID {
		return storage.ErrForbidden
	}
	delete(s.messages, id)
	return nil
}

func (s *Store) DeleteMessagesForDevice(_ context.Context, userID string, deviceID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for mid, m := range s.messages {
		if m.RecipientUserID == userID && m.RecipientDeviceID == deviceID {
			delete(s.messages, mid)
		}
	}
	return nil
}

func (s *Store) DeleteExpiredMessages(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for mid, m := range s.messages {
		if !m.TTLExpiresAt.After(now) {
			delete(s.messages, mid)
			n++
		}
	}
	return n, nil
}
