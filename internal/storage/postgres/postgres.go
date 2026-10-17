// Package postgres implements storage.Store on PostgreSQL via pgx.
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quietly-messenger/quietly-server/internal/id"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

// Store is the pgx-backed Store implementation.
type Store struct {
	pool *pgxpool.Pool
	ulid *id.ULID
}

// New builds a Store over the given pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, ulid: id.NewULID()}
}

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return storage.ErrConflict
	}
	return err
}

// --- Users ---

func (s *Store) CreateUser(ctx context.Context, username string) (*storage.User, error) {
	uid, err := id.UUIDv4()
	if err != nil {
		return nil, err
	}
	var u storage.User
	err = s.pool.QueryRow(ctx,
		`INSERT INTO users (id, username) VALUES ($1, $2)
		 RETURNING id::text, username, created_at`,
		uid, username,
	).Scan(&u.ID, &u.Username, &u.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	var u storage.User
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, username, created_at FROM users WHERE username = $1`,
		username,
	).Scan(&u.ID, &u.Username, &u.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

func (s *Store) GetUser(ctx context.Context, userID string) (*storage.User, error) {
	var u storage.User
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, username, created_at FROM users WHERE id = $1`,
		userID,
	).Scan(&u.ID, &u.Username, &u.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

// CreateAccountWithDevice creates an account and its device 1 in a single
// transaction, so a partial failure cannot leave a deviceless account (audit
// F-10).
func (s *Store) CreateAccountWithDevice(ctx context.Context, username string, d *storage.Device, prekeys []storage.OneTimePreKey) (*storage.User, *storage.Device, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	uid, err := id.UUIDv4()
	if err != nil {
		return nil, nil, err
	}

	var u storage.User
	err = tx.QueryRow(ctx,
		`INSERT INTO users (id, username) VALUES ($1, $2)
		 RETURNING id::text, username, created_at`,
		uid, username,
	).Scan(&u.ID, &u.Username, &u.CreatedAt)
	if err != nil {
		return nil, nil, mapErr(err)
	}

	var deviceID int
	err = tx.QueryRow(ctx,
		`INSERT INTO devices
		   (user_id, id, identity_key_dh, identity_key_sig, identity_binding,
		    signed_prekey_id, signed_prekey, signed_prekey_sig, delivery_token, delivery_token_hash)
		 VALUES ($1, (SELECT COALESCE(MAX(id),0)+1 FROM devices WHERE user_id = $1),
		         $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id`,
		uid, d.IdentityKeyDH, d.IdentityKeySig, d.IdentityBinding,
		d.SignedPreKeyID, d.SignedPreKey, d.SignedPreKeySig, d.DeliveryToken, d.DeliveryTokenHash,
	).Scan(&deviceID)
	if err != nil {
		return nil, nil, mapErr(err)
	}

	for _, p := range prekeys {
		if _, err := tx.Exec(ctx,
			`INSERT INTO one_time_prekeys (device_user_id, device_id, prekey_id, public_key)
			 VALUES ($1, $2, $3, $4)`,
			uid, deviceID, p.ID, p.PublicKey,
		); err != nil {
			return nil, nil, mapErr(err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	d.ID = deviceID
	d.UserID = uid
	return &u, d, nil
}

// --- Devices ---

func (s *Store) CreateDevice(ctx context.Context, d *storage.Device, prekeys []storage.OneTimePreKey) (*storage.Device, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the user row so concurrent device creation serializes, making
	// max(id)+1 a safe next-id assignment.
	if _, err := tx.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, d.UserID); err != nil {
		return nil, mapErr(err)
	}

	var deviceID int
	err = tx.QueryRow(ctx,
		`INSERT INTO devices
		   (user_id, id, identity_key_dh, identity_key_sig, identity_binding,
		    signed_prekey_id, signed_prekey, signed_prekey_sig, delivery_token, delivery_token_hash)
		 VALUES ($1, (SELECT COALESCE(MAX(id),0)+1 FROM devices WHERE user_id = $1),
		         $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id`,
		d.UserID, d.IdentityKeyDH, d.IdentityKeySig, d.IdentityBinding,
		d.SignedPreKeyID, d.SignedPreKey, d.SignedPreKeySig, d.DeliveryToken, d.DeliveryTokenHash,
	).Scan(&deviceID)
	if err != nil {
		return nil, mapErr(err)
	}

	for _, p := range prekeys {
		if _, err := tx.Exec(ctx,
			`INSERT INTO one_time_prekeys (device_user_id, device_id, prekey_id, public_key)
			 VALUES ($1, $2, $3, $4)`,
			d.UserID, deviceID, p.ID, p.PublicKey,
		); err != nil {
			return nil, mapErr(err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	d.ID = deviceID
	return d, nil
}

func (s *Store) GetDevice(ctx context.Context, userID string, deviceID int) (*storage.Device, error) {
	var d storage.Device
	var revokedAt *time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id::text, identity_key_dh, identity_key_sig, identity_binding,
		        signed_prekey_id, signed_prekey, signed_prekey_sig, signed_prekey_rotated_at,
		        delivery_token, delivery_token_hash,
		        created_at, revoked_at, push_endpoint
		 FROM devices WHERE user_id = $1 AND id = $2`,
		userID, deviceID,
	).Scan(&d.ID, &d.UserID, &d.IdentityKeyDH, &d.IdentityKeySig, &d.IdentityBinding,
		&d.SignedPreKeyID, &d.SignedPreKey, &d.SignedPreKeySig, &d.SignedPreKeyRotatedAt,
		&d.DeliveryToken, &d.DeliveryTokenHash,
		&d.CreatedAt, &revokedAt, &d.PushEndpoint)
	if err != nil {
		return nil, mapErr(err)
	}
	d.RevokedAt = revokedAt
	return &d, nil
}

func (s *Store) ListDevices(ctx context.Context, userID string) ([]storage.Device, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id::text, identity_key_dh, identity_key_sig, identity_binding,
		        signed_prekey_id, signed_prekey, signed_prekey_sig, signed_prekey_rotated_at,
		        delivery_token, delivery_token_hash,
		        created_at, revoked_at, push_endpoint
		 FROM devices WHERE user_id = $1 ORDER BY id`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []storage.Device
	for rows.Next() {
		var d storage.Device
		var revokedAt *time.Time
		if err := rows.Scan(&d.ID, &d.UserID, &d.IdentityKeyDH, &d.IdentityKeySig, &d.IdentityBinding,
			&d.SignedPreKeyID, &d.SignedPreKey, &d.SignedPreKeySig, &d.SignedPreKeyRotatedAt,
			&d.DeliveryToken, &d.DeliveryTokenHash,
			&d.CreatedAt, &revokedAt, &d.PushEndpoint); err != nil {
			return nil, err
		}
		d.RevokedAt = revokedAt
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) CountActiveDevices(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM devices WHERE user_id = $1 AND revoked_at IS NULL`,
		userID).Scan(&n)
	return n, err
}

func (s *Store) RevokeDevice(ctx context.Context, userID string, deviceID int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ct, err := tx.Exec(ctx,
		`UPDATE devices SET revoked_at = now()
		 WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL`,
		userID, deviceID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	// §2.2: revocation deletes the device's queued messages (audit F-11).
	if _, err := tx.Exec(ctx,
		`DELETE FROM messages WHERE recipient_user_id = $1 AND recipient_device_id = $2`,
		userID, deviceID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) UpdateSignedPreKey(ctx context.Context, userID string, deviceID int, spkID uint32, spk, sig []byte) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE devices
		 SET signed_prekey_id = $3, signed_prekey = $4, signed_prekey_sig = $5,
		     signed_prekey_rotated_at = now()
		 WHERE user_id = $1 AND id = $2`,
		userID, deviceID, spkID, spk, sig)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateDeliveryToken(ctx context.Context, userID string, deviceID int, token, tokenHash []byte) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE devices SET delivery_token = $3, delivery_token_hash = $4
		 WHERE user_id = $1 AND id = $2`,
		userID, deviceID, token, tokenHash)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) UpdatePushEndpoint(ctx context.Context, userID string, deviceID int, endpoint *string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE devices SET push_endpoint = $3 WHERE user_id = $1 AND id = $2`,
		userID, deviceID, endpoint)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// --- One-time prekeys ---

func (s *Store) AddOneTimePreKeys(ctx context.Context, userID string, deviceID int, prekeys []storage.OneTimePreKey) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, p := range prekeys {
		if _, err := tx.Exec(ctx,
			`INSERT INTO one_time_prekeys (device_user_id, device_id, prekey_id, public_key)
			 VALUES ($1, $2, $3, $4)`,
			userID, deviceID, p.ID, p.PublicKey); err != nil {
			return mapErr(err)
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) TakeOneTimePreKey(ctx context.Context, userID string, deviceID int) (*storage.OneTimePreKey, error) {
	var p storage.OneTimePreKey
	err := s.pool.QueryRow(ctx,
		`WITH picked AS (
		    SELECT prekey_id FROM one_time_prekeys
		    WHERE device_user_id = $1 AND device_id = $2 AND NOT used
		    ORDER BY prekey_id LIMIT 1 FOR UPDATE SKIP LOCKED
		 )
		 UPDATE one_time_prekeys SET used = true
		 FROM picked
		 WHERE one_time_prekeys.prekey_id = picked.prekey_id
		   AND one_time_prekeys.device_user_id = $1 AND one_time_prekeys.device_id = $2
		 RETURNING one_time_prekeys.prekey_id, one_time_prekeys.public_key`,
		userID, deviceID,
	).Scan(&p.ID, &p.PublicKey)
	if err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

func (s *Store) CountAvailablePreKeys(ctx context.Context, userID string, deviceID int) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM one_time_prekeys
		 WHERE device_user_id = $1 AND device_id = $2 AND NOT used`,
		userID, deviceID).Scan(&n)
	return n, err
}

func (s *Store) GetPreKeyIssuance(ctx context.Context, targetUserID string, targetDeviceID int, windowStart time.Time) (*storage.OneTimePreKey, time.Time, error) {
	var p storage.OneTimePreKey
	var at time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT prekey_id, public_key, issued_at FROM prekey_issuances
		 WHERE target_user_id = $1 AND target_device_id = $2 AND window_start = $3`,
		targetUserID, targetDeviceID, windowStart,
	).Scan(&p.ID, &p.PublicKey, &at)
	if err != nil {
		return nil, time.Time{}, mapErr(err)
	}
	return &p, at, nil
}

func (s *Store) RecordPreKeyIssuance(ctx context.Context, targetUserID string, targetDeviceID int, windowStart time.Time, prekey storage.OneTimePreKey) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO prekey_issuances
		   (target_user_id, target_device_id, window_start, prekey_id, public_key)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (target_user_id, target_device_id, window_start)
		 DO UPDATE SET prekey_id = EXCLUDED.prekey_id, public_key = EXCLUDED.public_key, issued_at = now()`,
		targetUserID, targetDeviceID, windowStart, prekey.ID, prekey.PublicKey,
	)
	return err
}

// PrunePreKeyIssuances deletes issuance records past the §7.2.1 idempotency
// window (audit F-02 residual).
func (s *Store) PrunePreKeyIssuances(ctx context.Context, before time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM prekey_issuances WHERE issued_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) DeleteMessagesForDevice(ctx context.Context, userID string, deviceID int) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM messages WHERE recipient_user_id = $1 AND recipient_device_id = $2`,
		userID, deviceID)
	return err
}

// --- Messages ---

func (s *Store) EnqueueMessage(ctx context.Context, m *storage.Message) error {
	if m.ID == "" {
		m.ID = s.ulid.Next()
	}
	if m.NotBefore.IsZero() {
		m.NotBefore = m.ServerTS
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO messages (id, recipient_user_id, recipient_device_id, sealed, server_ts, not_before, ttl_expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		m.ID, m.RecipientUserID, m.RecipientDeviceID, m.Sealed, m.ServerTS, m.NotBefore, m.TTLExpiresAt)
	return err
}

func (s *Store) ListMessages(ctx context.Context, userID string, deviceID int, now time.Time, limit int) ([]storage.Message, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, recipient_user_id::text, recipient_device_id, sealed, server_ts, not_before, ttl_expires_at
		 FROM messages
		 WHERE recipient_user_id = $1 AND recipient_device_id = $2 AND not_before <= $3
		 ORDER BY server_ts, id LIMIT $4`,
		userID, deviceID, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []storage.Message
	for rows.Next() {
		var m storage.Message
		if err := rows.Scan(&m.ID, &m.RecipientUserID, &m.RecipientDeviceID, &m.Sealed, &m.ServerTS, &m.NotBefore, &m.TTLExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// PendingMessages returns future-due messages (not_before > now) ordered by
// release time, for post-restart notification recovery (TASK-001 B).
func (s *Store) PendingMessages(ctx context.Context, now time.Time, limit int) ([]storage.Message, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, recipient_user_id::text, recipient_device_id, sealed, server_ts, not_before, ttl_expires_at
		 FROM messages
		 WHERE not_before > $1
		 ORDER BY not_before, id LIMIT $2`,
		now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []storage.Message
	for rows.Next() {
		var m storage.Message
		if err := rows.Scan(&m.ID, &m.RecipientUserID, &m.RecipientDeviceID, &m.Sealed, &m.ServerTS, &m.NotBefore, &m.TTLExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) AckMessage(ctx context.Context, userID string, deviceID int, id string) error {
	var rid string
	var rdev int
	err := s.pool.QueryRow(ctx,
		`SELECT recipient_user_id::text, recipient_device_id FROM messages WHERE id = $1`, id).
		Scan(&rid, &rdev)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.ErrNotFound
	}
	if err != nil {
		return err
	}
	if rid != userID || rdev != deviceID {
		return storage.ErrForbidden
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM messages WHERE id = $1`, id)
	return err
}

func (s *Store) DeleteExpiredMessages(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM messages WHERE ttl_expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
