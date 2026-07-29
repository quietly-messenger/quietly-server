package config

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"strconv"
)

type Config struct {
	ServerAddress  string
	ServerPort     int
	DatabaseURL    string
	MessageTTLDays int
	PowDifficulty  int
	LogLevel       slog.Level
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

	return cfg, nil
}
