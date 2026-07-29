package main

import (
	"log/slog"
	"os"

	"github.com/quietly-messenger/quietly-server/internal/config"
)

func main() {
	// Debug level, log everything, until reads real loglevel from config
	slog.SetLogLoggerLevel(slog.LevelDebug)
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}
	slog.Debug("Config loaded", "cfg", cfg)
}
