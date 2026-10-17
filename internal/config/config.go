package config

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ServerAddress  string
	ServerPort     int
	DatabaseURL    string
	MessageTTLDays int
	PowDifficulty  int
	LogLevel       slog.Level

	// WsAllowedOrigins lists browser origins allowed to open /v1/ws
	// (§13, WS_ALLOWED_ORIGINS, comma-separated). Native clients send no
	// Origin header and are unaffected.
	WsAllowedOrigins []string

	// Limits holds the PROTOCOL.md §15 parameters. They are optional and
	// defaulted; only SERVER_ADDR and DATABASE_URL are required.
	Limits Limits
}

// Limits holds the protocol's tunable parameters (PROTOCOL.md §15).
type Limits struct {
	MessageTTLDays        int // offline message expiry
	PowDifficulty         int // proof-of-work leading zero bits
	AuthSkewMs            int // request timestamp window
	PowWindowMs           int // proof-of-work freshness window
	MaxDevicesPerAccount  int
	OTPBatchSize          int // prekeys uploaded at registration
	OTPReplenishThreshold int // client tops up below this
	OTPMaxStored          int // server cap per device
	SealedBlobMax         int // payload_too_large above this
	FetchLimitMax         int // GET /v1/messages default cap
	SPKRotationDays       int // signed prekey rotation
	SPKGraceDays          int // previous signed prekey stays valid
	DeliveryTokenBytes    int
	BundleFetchPerHour    int // per-requesting-device bundle fetch limit (§15)
	RequestsPerMinute     int // per-IP general request limit
	WsPingIntervalS       int // server control-ping cadence
	WsIdleTimeoutS        int // close an idle socket after this
}

// DefaultLimits returns the documented §15 defaults, so callers (and tests)
// can start from a complete, valid Limits value.
func DefaultLimits() Limits {
	return Limits{
		MessageTTLDays:        30,
		PowDifficulty:         18,
		AuthSkewMs:            60_000,
		PowWindowMs:           300_000,
		MaxDevicesPerAccount:  5,
		OTPBatchSize:          100,
		OTPReplenishThreshold: 20,
		OTPMaxStored:          200,
		SealedBlobMax:         64 * 1024,
		FetchLimitMax:         500,
		SPKRotationDays:       3,
		SPKGraceDays:          3,
		DeliveryTokenBytes:    32,
		BundleFetchPerHour:    60,
		RequestsPerMinute:     120,
		WsPingIntervalS:       30,
		WsIdleTimeoutS:        90,
	}
}

func Load() (*Config, error) {
	cfg := &Config{}

	slog.Debug("Reading .env")

	/// Server address
	if addr := os.Getenv("SERVER_ADDR"); addr != "" {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, errors.New("SERVER_ADDR must be in the format: HOST:PORT")
		}
		if intPort, err := strconv.Atoi(port); err == nil {
			if intPort < 1 || intPort > 65535 {
				return nil, errors.New("SERVER_ADDR: port must be a valid port number (1-65535)")
			}
			cfg.ServerAddress = host
			cfg.ServerPort = intPort
		} else {
			return nil, errors.New("SERVER_ADDR: port must be a number")
		}
	} else {
		return nil, errors.New("SERVER_ADDR not set")
	}

	/// Database URL
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		cfg.DatabaseURL = dbURL
	} else {
		return nil, errors.New("DATABASE_URL not set")
	}
	if ttlDays := os.Getenv("MESSAGE_TTL_DAYS"); ttlDays != "" {
		ttl, err := strconv.Atoi(ttlDays)
		if err != nil {
			return nil, errors.New("MESSAGE_TTL_DAYS must be a number")
		}

		// MESSAGE_TTL_DAYS must be a positive integer
		if ttl < 1 {
			return nil, errors.New("MESSAGE_TTL_DAYS must be a positive integer")
		}
		cfg.MessageTTLDays = ttl
	} else {
		return nil, errors.New("MESSAGE_TTL_DAYS not set")
	}

	/// POW difficulty
	if powDifficulty := os.Getenv("POW_DIFFICULTY"); powDifficulty != "" {
		difficulty, err := strconv.Atoi(powDifficulty)
		if err != nil {
			return nil, errors.New("POW_DIFFICULTY must be a number")
		}

		if difficulty < 1 || difficulty > 32 {
			return nil, errors.New("POW_DIFFICULTY must be between 1 and 32")
		}
		cfg.PowDifficulty = difficulty
	} else {
		return nil, errors.New("POW_DIFFICULTY not set")
	}

	/// Log level
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		switch logLevel {
		case "debug":
			cfg.LogLevel = slog.LevelDebug
		case "info":
			cfg.LogLevel = slog.LevelInfo
		case "warn":
			cfg.LogLevel = slog.LevelWarn
		case "error":
			cfg.LogLevel = slog.LevelError
		default:
			return nil, errors.New("invalid LOG_LEVEL. must be one of: debug, info, warn, error")
		}
		slog.SetLogLoggerLevel(cfg.LogLevel)
	} else {
		return nil, errors.New("LOG_LEVEL not set")
	}

	cfg.Limits = loadLimits()
	cfg.Limits.MessageTTLDays = cfg.MessageTTLDays
	cfg.Limits.PowDifficulty = cfg.PowDifficulty
	cfg.WsAllowedOrigins = envList("WS_ALLOWED_ORIGINS")

	return cfg, nil
}

// loadLimits reads the optional §15 parameters from the environment, falling
// back to the documented defaults for anything unset or unparseable.
func loadLimits() Limits {
	l := DefaultLimits()
	if v := envInt("AUTH_SKEW_MS"); v > 0 {
		l.AuthSkewMs = v
	}
	if v := envInt("POW_WINDOW_MS"); v > 0 {
		l.PowWindowMs = v
	}
	if v := envInt("MAX_DEVICES_PER_ACCOUNT"); v > 0 {
		l.MaxDevicesPerAccount = v
	}
	if v := envInt("OTP_BATCH_SIZE"); v > 0 {
		l.OTPBatchSize = v
	}
	if v := envInt("OTP_REPLENISH_THRESHOLD"); v > 0 {
		l.OTPReplenishThreshold = v
	}
	if v := envInt("OTP_MAX_STORED"); v > 0 {
		l.OTPMaxStored = v
	}
	if v := envInt("SEALED_BLOB_MAX"); v > 0 {
		l.SealedBlobMax = v
	}
	if v := envInt("FETCH_LIMIT_MAX"); v > 0 {
		l.FetchLimitMax = v
	}
	if v := envInt("SPK_ROTATION_DAYS"); v > 0 {
		l.SPKRotationDays = v
	}
	if v := envInt("SPK_GRACE_DAYS"); v > 0 {
		l.SPKGraceDays = v
	}
	if v := envInt("DELIVERY_TOKEN_BYTES"); v > 0 {
		l.DeliveryTokenBytes = v
	}
	if v := envInt("BUNDLE_FETCH_PER_HOUR"); v > 0 {
		l.BundleFetchPerHour = v
	}
	if v := envInt("REQUESTS_PER_MINUTE"); v > 0 {
		l.RequestsPerMinute = v
	}
	if v := envInt("WS_PING_INTERVAL_S"); v > 0 {
		l.WsPingIntervalS = v
	}
	if v := envInt("WS_IDLE_TIMEOUT_S"); v > 0 {
		l.WsIdleTimeoutS = v
	}
	return l
}

// envInt reads an integer environment variable, returning 0 if unset or not a
// positive integer.
func envInt(name string) int {
	v := os.Getenv(name)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

// envList reads a comma-separated environment variable.
func envList(name string) []string {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(v, ",") {
		if s := strings.TrimSpace(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}
