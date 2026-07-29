package config

import (
	"log/slog"
	"strings"
	"testing"
)

// knownEnvVars is every variable Load actually reads. Error messages must name
// one of these and nothing else — a message naming a variable that does not
// exist sends the reader looking for something they will never find.
var knownEnvVars = []string{
	"SERVER_ADDR",
	"DATABASE_URL",
	"MESSAGE_TTL_DAYS",
	"POW_DIFFICULTY",
	"LOG_LEVEL",
}

// setValidEnv puts a complete, valid configuration in the environment. Tests
// override single variables from here so that every failure is attributable to
// exactly one field.
//
// Empty string is used to mean "unset": Load treats "" and unset identically,
// and t.Setenv restores whatever the test runner inherited from the Makefile.
func setValidEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SERVER_ADDR", "0.0.0.0:8080")
	t.Setenv("DATABASE_URL", "postgresql://quietly:quietly@localhost:5432/quietly?sslmode=disable")
	t.Setenv("MESSAGE_TTL_DAYS", "30")
	t.Setenv("POW_DIFFICULTY", "18")
	t.Setenv("LOG_LEVEL", "info")
}

// restoreLogLevel undoes Load's global side effect on the default logger.
// Without this, a test that loads LOG_LEVEL=debug leaves the whole test binary
// in debug for every test that follows it.
func restoreLogLevel(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { slog.SetLogLoggerLevel(slog.LevelInfo) })
}

func TestLoadValid(t *testing.T) {
	restoreLogLevel(t)
	setValidEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error for valid config: %v", err)
	}

	if cfg.ServerAddress != "0.0.0.0" {
		t.Errorf("ServerAddress = %q, want %q", cfg.ServerAddress, "0.0.0.0")
	}
	if cfg.ServerPort != 8080 {
		t.Errorf("ServerPort = %d, want %d", cfg.ServerPort, 8080)
	}
	if cfg.DatabaseURL == "" {
		t.Error("DatabaseURL is empty")
	}
	if cfg.MessageTTLDays != 30 {
		t.Errorf("MessageTTLDays = %d, want %d", cfg.MessageTTLDays, 30)
	}
	if cfg.PowDifficulty != 18 {
		t.Errorf("PowDifficulty = %d, want %d", cfg.PowDifficulty, 18)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, slog.LevelInfo)
	}
}

// TestServerAddr covers the parsing of SERVER_ADDR. The localhost case is a
// regression test: an earlier implementation stored a net.Addr built from
// net.ParseIP, which silently dropped any non-IP host and turned a
// loopback-only binding into a bind on every interface.
func TestServerAddr(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{name: "ipv4 with port", addr: "0.0.0.0:8080", wantHost: "0.0.0.0", wantPort: 8080},
		{name: "hostname is preserved", addr: "localhost:8080", wantHost: "localhost", wantPort: 8080},
		{name: "empty host means all interfaces", addr: ":8080", wantHost: "", wantPort: 8080},
		{name: "ipv6 with port", addr: "[::1]:8080", wantHost: "::1", wantPort: 8080},
		{name: "unset", addr: "", wantErr: true},
		{name: "missing port", addr: "0.0.0.0", wantErr: true},
		{name: "non-numeric port", addr: "0.0.0.0:http", wantErr: true},
		{name: "port above range", addr: "0.0.0.0:99999", wantErr: true},
		{name: "port zero", addr: "0.0.0.0:0", wantErr: true},
		{name: "negative port", addr: "0.0.0.0:-1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreLogLevel(t)
			setValidEnv(t)
			t.Setenv("SERVER_ADDR", tt.addr)

			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() = no error for SERVER_ADDR=%q, want error", tt.addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error for SERVER_ADDR=%q: %v", tt.addr, err)
			}
			if cfg.ServerAddress != tt.wantHost {
				t.Errorf("ServerAddress = %q, want %q", cfg.ServerAddress, tt.wantHost)
			}
			if cfg.ServerPort != tt.wantPort {
				t.Errorf("ServerPort = %d, want %d", cfg.ServerPort, tt.wantPort)
			}
		})
	}
}

func TestDatabaseURL(t *testing.T) {
	restoreLogLevel(t)
	setValidEnv(t)
	t.Setenv("DATABASE_URL", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() = no error for unset DATABASE_URL, want error")
	}
}

// TestMessageTTLDays guards the value that decides when undelivered messages
// are destroyed. Zero or negative would expire every message the instant it
// arrives, which looks like message loss rather than a config mistake.
func TestMessageTTLDays(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    int
		wantErr bool
	}{
		{name: "documented default", value: "30", want: 30},
		{name: "one day", value: "1", want: 1},
		{name: "unset", value: "", wantErr: true},
		{name: "non-numeric", value: "abc", wantErr: true},
		{name: "zero expires everything immediately", value: "0", wantErr: true},
		{name: "negative", value: "-5", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreLogLevel(t)
			setValidEnv(t)
			t.Setenv("MESSAGE_TTL_DAYS", tt.value)

			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() = no error for MESSAGE_TTL_DAYS=%q, want error", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error for MESSAGE_TTL_DAYS=%q: %v", tt.value, err)
			}
			if cfg.MessageTTLDays != tt.want {
				t.Errorf("MessageTTLDays = %d, want %d", cfg.MessageTTLDays, tt.want)
			}
		})
	}
}

// TestPowDifficulty guards an anti-abuse control. Zero disables proof of work
// entirely and turns registration into an open endpoint, so a typo in .env must
// not be able to reach it.
func TestPowDifficulty(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    int
		wantErr bool
	}{
		{name: "spec default", value: "18", want: 18},
		{name: "lower bound", value: "1", want: 1},
		{name: "upper bound", value: "32", want: 32},
		{name: "unset", value: "", wantErr: true},
		{name: "non-numeric", value: "abc", wantErr: true},
		{name: "zero disables proof of work", value: "0", wantErr: true},
		{name: "negative", value: "-1", wantErr: true},
		{name: "above upper bound", value: "33", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreLogLevel(t)
			setValidEnv(t)
			t.Setenv("POW_DIFFICULTY", tt.value)

			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() = no error for POW_DIFFICULTY=%q, want error", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error for POW_DIFFICULTY=%q: %v", tt.value, err)
			}
			if cfg.PowDifficulty != tt.want {
				t.Errorf("PowDifficulty = %d, want %d", cfg.PowDifficulty, tt.want)
			}
		})
	}
}

func TestLogLevel(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    slog.Level
		wantErr bool
	}{
		{name: "debug", value: "debug", want: slog.LevelDebug},
		{name: "info", value: "info", want: slog.LevelInfo},
		{name: "warn", value: "warn", want: slog.LevelWarn},
		{name: "error", value: "error", want: slog.LevelError},
		{name: "unset", value: "", wantErr: true},
		{name: "unknown level", value: "trace", wantErr: true},
		// The README documents lowercase. Accepting other spellings silently
		// would make the documented set a lie.
		{name: "uppercase is not documented", value: "DEBUG", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreLogLevel(t)
			setValidEnv(t)
			t.Setenv("LOG_LEVEL", tt.value)

			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() = no error for LOG_LEVEL=%q, want error", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error for LOG_LEVEL=%q: %v", tt.value, err)
			}
			if cfg.LogLevel != tt.want {
				t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, tt.want)
			}
		})
	}
}

// TestErrorsNameTheOffendingVariable checks that every failure path says which
// environment variable is wrong, and names one that actually exists. Reading
// "strconv.Atoi: parsing \"abc\"" at three in the morning tells you nothing
// about which of five variables to look at.
func TestErrorsNameTheOffendingVariable(t *testing.T) {
	tests := []struct {
		name    string
		envVar  string
		value   string
		wantVar string
	}{
		{name: "server addr unset", envVar: "SERVER_ADDR", value: "", wantVar: "SERVER_ADDR"},
		{name: "server addr malformed", envVar: "SERVER_ADDR", value: "not-an-address", wantVar: "SERVER_ADDR"},
		{name: "server addr bad port", envVar: "SERVER_ADDR", value: "0.0.0.0:http", wantVar: "SERVER_ADDR"},
		{name: "database url unset", envVar: "DATABASE_URL", value: "", wantVar: "DATABASE_URL"},
		{name: "ttl unset", envVar: "MESSAGE_TTL_DAYS", value: "", wantVar: "MESSAGE_TTL_DAYS"},
		{name: "ttl not a number", envVar: "MESSAGE_TTL_DAYS", value: "abc", wantVar: "MESSAGE_TTL_DAYS"},
		{name: "pow unset", envVar: "POW_DIFFICULTY", value: "", wantVar: "POW_DIFFICULTY"},
		{name: "pow not a number", envVar: "POW_DIFFICULTY", value: "abc", wantVar: "POW_DIFFICULTY"},
		{name: "pow out of range", envVar: "POW_DIFFICULTY", value: "99", wantVar: "POW_DIFFICULTY"},
		{name: "log level unset", envVar: "LOG_LEVEL", value: "", wantVar: "LOG_LEVEL"},
		{name: "log level unknown", envVar: "LOG_LEVEL", value: "trace", wantVar: "LOG_LEVEL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreLogLevel(t)
			setValidEnv(t)
			t.Setenv(tt.envVar, tt.value)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load() = no error for %s=%q, want error", tt.envVar, tt.value)
			}
			msg := err.Error()

			if !strings.Contains(msg, tt.wantVar) {
				t.Errorf("error %q does not name %s", msg, tt.wantVar)
			}

			// Catch messages that name a variable which does not exist, such as
			// SERVER_ADDRESS when the variable read is SERVER_ADDR.
			for _, token := range strings.Fields(strings.ReplaceAll(msg, ".", " ")) {
				if !isUpperSnake(token) || token == tt.wantVar {
					continue
				}
				if !slicesContains(knownEnvVars, token) {
					t.Errorf("error %q names %q, which is not a variable this package reads", msg, token)
				}
			}
		})
	}
}

func isUpperSnake(s string) bool {
	if len(s) < 2 {
		return false
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && r != '_' {
			return false
		}
	}
	return true
}

func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
