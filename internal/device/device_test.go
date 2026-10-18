package device_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
	"github.com/quietly-messenger/quietly-crypto/identity"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/device"
	"github.com/quietly-messenger/quietly-server/internal/message"
	"github.com/quietly-messenger/quietly-server/internal/storage/memory"
	"github.com/quietly-messenger/quietly-server/internal/testutil"
)

func TestRegisterEnforcesDeviceLimit(t *testing.T) {
	store := memory.New()
	limits := testutil.Limits()
	alice := testutil.NewAccount(t, store, limits, "alice")
	svc := device.New(store, limits)

	for i := 0; i < limits.MaxDevicesPerAccount-1; i++ {
		testutil.AddDevice(t, store, limits, alice.UserID)
	}
	// One more exceeds max_devices_per_account.
	_, reg := testutil.Registration(t, limits.DeliveryTokenBytes, 1)
	_, err := svc.Register(context.Background(), alice.UserID, reg)
	if code := apiCode(t, err); code != api.CodeDeviceLimitReached {
		t.Fatalf("code=%q err=%v", code, err)
	}
}

// TestPreKeyBundleConsumesAndIsIdempotent covers §7.2.1 mitigation 2: a repeat
// fetch by the same requester returns the same prekey; a different requester
// gets a different one.
func TestPreKeyBundleIdempotentPerTargetWindow(t *testing.T) {
	store := memory.New()
	limits := testutil.Limits()
	alice := testutil.NewAccount(t, store, limits, "alice", 1, 2, 3) // target with prekeys
	bob := testutil.NewAccount(t, store, limits, "bob", 4, 5, 6)     // another target
	svc := device.New(store, limits)
	ctx := context.Background()
	now := time.Now()

	first, _, err := svc.PreKeyBundle(ctx, alice.UserID, alice.DeviceID, now)
	if err != nil {
		t.Fatalf("first bundle: %v", err)
	}
	if first.OneTimePrekey == nil {
		t.Fatal("expected a one-time prekey")
	}
	remainingAfterFirst := first.OneTimePrekeysRemaining

	// Same target, same window: identical prekey, nothing more consumed. This
	// is the per-(target, window) idempotency of TASK-001 C: the *requester*
	// is not part of the key.
	again, _, err := svc.PreKeyBundle(ctx, alice.UserID, alice.DeviceID, now)
	if err != nil {
		t.Fatalf("repeat bundle: %v", err)
	}
	if again.OneTimePrekey == nil || again.OneTimePrekey.ID != first.OneTimePrekey.ID {
		t.Fatalf("idempotency broken: first=%v again=%v", first.OneTimePrekey, again.OneTimePrekey)
	}
	if again.OneTimePrekeysRemaining != remainingAfterFirst {
		t.Fatalf("remaining changed on idempotent fetch: %d != %d",
			again.OneTimePrekeysRemaining, remainingAfterFirst)
	}

	// A different target is a different record.
	other, _, err := svc.PreKeyBundle(ctx, bob.UserID, bob.DeviceID, now)
	if err != nil {
		t.Fatalf("other bundle: %v", err)
	}
	if other.OneTimePrekey == nil || other.OneTimePrekey.ID == first.OneTimePrekey.ID {
		t.Fatalf("different target reused prekey %v", other.OneTimePrekey)
	}
}

// TestPreKeyBundleWindowAdvances proves the idempotency window is a fixed 24 h
// bucket: a fetch in the next window consumes a fresh OTPK (the documented
// forward-secrecy relaxation is per-window, TASK-001 C).
func TestPreKeyBundleWindowAdvances(t *testing.T) {
	store := memory.New()
	limits := testutil.Limits()
	alice := testutil.NewAccount(t, store, limits, "alice", 1, 2, 3)
	svc := device.New(store, limits)
	ctx := context.Background()
	now := time.Now()

	first, _, err := svc.PreKeyBundle(ctx, alice.UserID, alice.DeviceID, now)
	if err != nil {
		t.Fatalf("first bundle: %v", err)
	}
	second, _, err := svc.PreKeyBundle(ctx, alice.UserID, alice.DeviceID, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("second bundle: %v", err)
	}
	if second.OneTimePrekey == nil {
		t.Fatal("expected a prekey")
	}
	if second.OneTimePrekey.ID == first.OneTimePrekey.ID {
		t.Fatalf("next window returned the same prekey %d", first.OneTimePrekey.ID)
	}
}

// TestPreKeyBundleConcurrentFetchesShareOneOTPK is the permanent regression for
// audit F-27: §7.2.1 mitigation 2 promises "one OTPK per target per window
// regardless of how many distinct clients fetch", including fetches that race
// before any issuance record exists. Concurrent bundles must all return the
// same OTPK and consume exactly one.
func TestPreKeyBundleConcurrentFetchesShareOneOTPK(t *testing.T) {
	store := memory.New()
	limits := testutil.Limits()
	ids := make([]uint32, 64)
	for i := range ids {
		ids[i] = uint32(i + 1)
	}
	alice := testutil.NewAccount(t, store, limits, "alice", ids...)
	svc := device.New(store, limits)
	ctx := context.Background()
	now := time.Now()

	const G = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	distinct := map[uint32]int{}
	for i := 0; i < G; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, _, err := svc.PreKeyBundle(ctx, alice.UserID, alice.DeviceID, now)
			if err != nil {
				t.Errorf("bundle: %v", err)
				return
			}
			if resp.OneTimePrekey == nil {
				return
			}
			mu.Lock()
			distinct[resp.OneTimePrekey.ID]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if len(distinct) != 1 {
		t.Fatalf("concurrent fetches handed out %d distinct OTPKs, want exactly 1", len(distinct))
	}
	rem, err := store.CountAvailablePreKeys(ctx, alice.UserID, alice.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if rem != len(ids)-1 {
		t.Fatalf("remaining prekeys = %d, want %d (exactly one consumed)", rem, len(ids)-1)
	}
}

func TestPreKeyBundleExhaustionReturnsNoPrekey(t *testing.T) {
	store := memory.New()
	limits := testutil.Limits()
	alice := testutil.NewAccount(t, store, limits, "alice", 1, 2) // two prekeys
	svc := device.New(store, limits)
	ctx := context.Background()
	now := time.Now()

	for i := 0; i < 2; i++ {
		resp, _, err := svc.PreKeyBundle(ctx, alice.UserID, alice.DeviceID, now.Add(time.Duration(i)*24*time.Hour))
		if err != nil {
			t.Fatalf("bundle %d: %v", i, err)
		}
		if resp.OneTimePrekey == nil {
			t.Fatalf("bundle %d: expected prekey", i)
		}
	}
	// A third window is exhausted: one_time_prekey is null and that is not an
	// error (§7.2).
	resp, _, err := svc.PreKeyBundle(ctx, alice.UserID, alice.DeviceID, now.Add(48*time.Hour))
	if err != nil {
		t.Fatalf("exhausted bundle: %v", err)
	}
	if resp.OneTimePrekey != nil {
		t.Fatalf("expected null prekey, got %v", resp.OneTimePrekey)
	}
	if resp.OneTimePrekeysRemaining != 0 {
		t.Fatalf("remaining=%d, want 0", resp.OneTimePrekeysRemaining)
	}
}

func TestAddPreKeysLimitsAndConflicts(t *testing.T) {
	store := memory.New()
	limits := testutil.Limits()
	alice := testutil.NewAccount(t, store, limits, "alice") // prekeys 1..5
	svc := device.New(store, limits)
	ctx := context.Background()

	t.Run("rejects duplicate existing id", func(t *testing.T) {
		_, err := svc.AddPreKeys(ctx, alice.UserID, alice.DeviceID, api.PrekeysRequest{
			V:              api.Version,
			OneTimePrekeys: []api.PreKey{{ID: 1, PublicKey: pub(t)}},
		})
		if code := apiCode(t, err); code != api.CodePrekeyIDConflict {
			t.Fatalf("code=%q err=%v", code, err)
		}
	})

	t.Run("rejects batch over the stored cap", func(t *testing.T) {
		var batch []api.PreKey
		for i := 0; i < limits.OTPMaxStored; i++ {
			batch = append(batch, api.PreKey{ID: uint32(1000 + i), PublicKey: pub(t)})
		}
		_, err := svc.AddPreKeys(ctx, alice.UserID, alice.DeviceID, api.PrekeysRequest{
			V: api.Version, OneTimePrekeys: batch,
		})
		if code := apiCode(t, err); code != api.CodePrekeyLimitExceeded {
			t.Fatalf("code=%q err=%v", code, err)
		}
	})

	t.Run("failed batch is not partially applied", func(t *testing.T) {
		// Second entry duplicates an existing prekey: the whole batch must be
		// rejected and the first entry must not land.
		_, err := svc.AddPreKeys(ctx, alice.UserID, alice.DeviceID, api.PrekeysRequest{
			V: api.Version,
			OneTimePrekeys: []api.PreKey{
				{ID: 900, PublicKey: pub(t)},
				{ID: 2, PublicKey: pub(t)},
			},
		})
		if code := apiCode(t, err); code != api.CodePrekeyIDConflict {
			t.Fatalf("code=%q err=%v", code, err)
		}
		if _, err := store.GetDevice(ctx, alice.UserID, alice.DeviceID); err != nil {
			t.Fatal(err)
		}
		// Prekey 900 must not exist: count stays at 5 (1..5).
		n, err := store.CountAvailablePreKeys(ctx, alice.UserID, alice.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		if n != 5 {
			t.Fatalf("available prekeys=%d, want 5 (batch partially applied)", n)
		}
	})
}

func TestUpdateSignedPreKeyVerifiesSignatureAndReportsRotation(t *testing.T) {
	store := memory.New()
	limits := testutil.Limits()
	alice := testutil.NewAccount(t, store, limits, "alice")
	svc := device.New(store, limits)
	ctx := context.Background()

	newSPK, err := cryptocore.GeneratePreKey()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("rejects bad signature", func(t *testing.T) {
		err := svc.UpdateSignedPreKey(ctx, alice.UserID, alice.DeviceID, api.SignedPrekeyRequest{
			V: api.Version,
			SignedPrekey: api.SignedPreKey{
				ID:        2,
				PublicKey: newSPK.PublicKey,
				Signature: make([]byte, 64),
			},
		})
		if code := apiCode(t, err); code != api.CodeSignatureInvalid {
			t.Fatalf("code=%q err=%v", code, err)
		}
	})

	sig, err := identity.SignSignedPreKey(alice.Keys.SigPriv, 2, newSPK.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateSignedPreKey(ctx, alice.UserID, alice.DeviceID, api.SignedPrekeyRequest{
		V:            api.Version,
		SignedPrekey: api.SignedPreKey{ID: 2, PublicKey: newSPK.PublicKey, Signature: sig},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	resp, rotatedAt, err := svc.PreKeyBundle(ctx, alice.UserID, alice.DeviceID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if resp.SignedPreKey.ID != 2 {
		t.Fatalf("bundle returned spk %d, want 2", resp.SignedPreKey.ID)
	}
	if time.Since(rotatedAt) > time.Minute {
		t.Fatalf("rotatedAt not refreshed: %s ago", time.Since(rotatedAt))
	}
}

func TestRevokePurgesQueuedMessages(t *testing.T) {
	store := memory.New()
	limits := testutil.Limits()
	alice := testutil.NewAccount(t, store, limits, "alice")
	bob := testutil.NewAccount(t, store, limits, "bob")
	msgs := message.New(store, limits)
	svc := device.New(store, limits)
	ctx := context.Background()

	// Bob sends Alice a message using her delivery token.
	m, err := msgs.Submit(ctx, api.MessageSubmit{
		V:         api.Version,
		Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.DeviceID},
		Sealed:    make([]byte, 128),
	}, alice.Token, time.Now())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := store.GetDevice(ctx, bob.UserID, bob.DeviceID); err != nil {
		t.Fatal(err)
	}

	if err := svc.Revoke(ctx, alice.UserID, alice.DeviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	list, err := store.ListMessages(ctx, alice.UserID, alice.DeviceID, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("queued messages survived revocation: %v", m.ID)
	}
}

func TestVerifyRegistrationRejectsUnsignedAndZeroIDs(t *testing.T) {
	limits := testutil.Limits()

	_, reg := testutil.Registration(t, limits.DeliveryTokenBytes, 1)
	bad := reg
	bad.IdentityBinding = make([]byte, 64)
	if err := device.VerifyRegistration(bad, limits.DeliveryTokenBytes); err == nil {
		t.Fatal("unsigned binding accepted")
	}

	_, reg = testutil.Registration(t, limits.DeliveryTokenBytes, 0)
	if err := device.VerifyRegistration(reg, limits.DeliveryTokenBytes); err == nil {
		t.Fatal("prekey id 0 accepted")
	}

	_, reg = testutil.Registration(t, limits.DeliveryTokenBytes, 7, 7)
	if err := device.VerifyRegistration(reg, limits.DeliveryTokenBytes); err == nil {
		t.Fatal("duplicate prekey ids accepted")
	}

	_, reg = testutil.Registration(t, limits.DeliveryTokenBytes, 7)
	reg.DeliveryToken = reg.DeliveryToken[:16]
	if err := device.VerifyRegistration(reg, limits.DeliveryTokenBytes); err == nil {
		t.Fatal("short delivery token accepted")
	}
}

func pub(t *testing.T) []byte {
	t.Helper()
	p, err := cryptocore.GeneratePreKey()
	if err != nil {
		t.Fatal(err)
	}
	return p.PublicKey
}

func apiCode(t *testing.T, err error) api.ErrorCode {
	t.Helper()
	if err == nil {
		return ""
	}
	if ae := api.AsAPIError(err); ae != nil {
		return ae.Code
	}
	t.Fatalf("non-API error: %v", err)
	return ""
}
