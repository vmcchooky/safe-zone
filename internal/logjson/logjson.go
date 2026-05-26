package logjson

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

var writeMu sync.Mutex

func Info(message string, fields map[string]any) {
	write("info", message, fields)
}

func Warn(message string, fields map[string]any) {
	write("warn", message, fields)
}

func Error(message string, fields map[string]any) {
	write("error", message, fields)
}

func write(level string, message string, fields map[string]any) {
	payload := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"level":   level,
		"message": message,
	}
	for key, value := range fields {
		payload[key] = value
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}

	writeMu.Lock()
	defer writeMu.Unlock()
	_, _ = os.Stdout.Write(append(encoded, '\n'))
}
