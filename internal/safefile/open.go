package safefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	*os.File
	root *os.Root
}

// DefaultMaxReadBytes bounds ReadFileWithin and ReadFile. The callers read
// secrets, checksums, configs and eval corpora -- the largest legitimate input
// today is a 13KB corpus file -- so a megabyte of headroom is generous while
// still making a compromised or accidentally enormous file in a trusted
// directory a bounded error instead of unbounded memory growth. A caller that
// streams (OpenWithin) is unaffected; only the convenience whole-file readers
// are capped, following the same LimitReader(n+1) pattern the feed code uses.
const DefaultMaxReadBytes = 1 << 20

// OpenWithin opens requestedPath through an os.Root scoped to rootDir.
// requestedPath may be relative to rootDir, or it may be an existing documented
// root-prefixed path. Paths outside rootDir are rejected before final resolution,
// and Go's os.Root blocks any traversal escaping the sandbox.
func OpenWithin(rootDir, requestedPath string) (*File, error) {
	relativePath, err := relativeWithinRoot(rootDir, requestedPath)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root sandbox %q: %w", rootDir, err)
	}

	file, err := root.Open(relativePath)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("failed to open file inside sandbox %q: %w", relativePath, err)
	}

	return &File{File: file, root: root}, nil
}

// Open opens a path relative to the current directory.
// For caller-controlled paths that should be sandboxed to a fixed root, use OpenWithin instead.
func Open(path string) (*File, error) {
	if path == "" {
		return nil, errors.New("file path is required")
	}

	// First, check if path resides within a trusted base directory to resolve it safely
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err == nil {
		cwd, err := filepath.Abs(".")
		if err == nil {
			// Secrets directory
			secretsDir := os.Getenv("SAFE_ZONE_SECRETS_DIR")
			if secretsDir == "" {
				secretsDir = filepath.Join(cwd, "ops", "secrets")
			}
			absSecrets, _ := filepath.Abs(secretsDir)

			// Data directory
			sqlitePath := os.Getenv("SAFE_ZONE_SQLITE_PATH")
			var dataDir string
			if sqlitePath != "" {
				dataDir = filepath.Dir(sqlitePath)
			} else {
				dataDir = filepath.Join(cwd, "data")
			}
			absData, _ := filepath.Abs(dataDir)

			roots := []string{cwd}
			if absSecrets != "" {
				roots = append(roots, absSecrets)
			}
			if absData != "" {
				roots = append(roots, absData)
			}

			for _, rPath := range roots {
				rel, err := filepath.Rel(rPath, absPath)
				if err == nil && !strings.HasPrefix(rel, "..") && rel != ".." {
					return OpenWithin(rPath, rel)
				}
			}
		}
	}

	// Fallback to local workspace sandboxing
	return OpenWithin(".", path)
}

func (f *File) Close() error {
	if f == nil {
		return nil
	}

	fileErr := f.File.Close()
	rootErr := f.root.Close()
	if fileErr != nil {
		return fileErr
	}
	return rootErr
}

// ReadFileWithin reads requestedPath using OpenWithin.
func ReadFileWithin(rootDir, requestedPath string) ([]byte, error) {
	file, err := OpenWithin(rootDir, requestedPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	return readBounded(file, requestedPath)
}

// ReadFile reads a path relative to the current directory.
// For caller-controlled paths that should be sandboxed, use ReadFileWithin instead.
func ReadFile(path string) ([]byte, error) {
	file, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	return readBounded(file, path)
}

// readBounded drains at most DefaultMaxReadBytes from an already-opened safe
// file. Reading one byte past the limit distinguishes "exactly at the limit",
// which succeeds, from "over the limit", which fails with the limit named so
// the operator can tell a misconfigured path from a genuinely oversized file.
func readBounded(file *File, displayPath string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(file, DefaultMaxReadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", displayPath, err)
	}
	if len(body) > DefaultMaxReadBytes {
		return nil, fmt.Errorf("refusing to read %q: size exceeds %d bytes", displayPath, DefaultMaxReadBytes)
	}
	return body, nil
}

func relativeWithinRoot(rootDir, requestedPath string) (string, error) {
	if strings.TrimSpace(rootDir) == "" {
		return "", errors.New("safe file root is required")
	}
	if strings.TrimSpace(requestedPath) == "" {
		return "", errors.New("file path is required")
	}

	rootAbs, err := filepath.Abs(filepath.Clean(rootDir))
	if err != nil {
		return "", err
	}

	cleaned := filepath.Clean(requestedPath)
	var rel string
	if filepath.IsAbs(cleaned) {
		rel, err = filepath.Rel(rootAbs, cleaned)
		if err != nil {
			return "", err
		}
	} else if absRequested, absErr := filepath.Abs(cleaned); absErr == nil && isWithin(rootAbs, absRequested) {
		rel, err = filepath.Rel(rootAbs, absRequested)
		if err != nil {
			return "", err
		}
	} else {
		rel = cleaned
	}

	rel = filepath.Clean(rel)
	if rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("file path escapes safe root")
	}

	return rel, nil
}

func isWithin(rootAbs, targetAbs string) bool {
	rel, err := filepath.Rel(rootAbs, filepath.Clean(targetAbs))
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
