package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken = errors.New("invalid session token")
	ErrExpiredToken = errors.New("session token expired")
)

const (
	RoleAdmin = "admin"
	RoleGuest = "guest"
)

// SessionClaims represents the payload stored inside the signed session cookie.
type SessionClaims struct {
	Username  string `json:"username"`
	Role      string `json:"role,omitempty"`
	ExpiresAt int64  `json:"expires_at"` // Unix timestamp
}

// GenerateSecureRandomString generates a cryptographically secure random hex string of the given byte length.
func GenerateSecureRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// SignToken generates an HMAC-SHA256 signature for the given data string using the secret key.
func SignToken(data string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// VerifyToken verifies if the HMAC-SHA256 signature for the given data matches the provided signature.
func VerifyToken(data, signature string, secret []byte) bool {
	expectedSig := SignToken(data, secret)
	return hmac.Equal([]byte(signature), []byte(expectedSig))
}

// GenerateSessionCookieValue creates a signed session token containing claims.
func GenerateSessionCookieValue(username string, duration time.Duration, secret []byte) (string, error) {
	return GenerateSessionCookieValueForRole(username, "", duration, secret)
}

func GenerateSessionCookieValueForRole(username, role string, duration time.Duration, secret []byte) (string, error) {
	claims := SessionClaims{
		Username:  username,
		Role:      NormalizeRole(username, role),
		ExpiresAt: time.Now().Add(duration).Unix(),
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session claims: %w", err)
	}

	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := SignToken(payload, secret)

	return fmt.Sprintf("%s.%s", payload, signature), nil
}

// VerifySessionCookieValue validates the signed cookie token and returns the username if valid.
func VerifySessionCookieValue(cookieVal string, secret []byte) (string, error) {
	claims, err := VerifySessionClaims(cookieVal, secret)
	if err != nil {
		return "", err
	}
	return claims.Username, nil
}

func VerifySessionClaims(cookieVal string, secret []byte) (SessionClaims, error) {
	parts := strings.Split(cookieVal, ".")
	if len(parts) != 2 {
		return SessionClaims{}, ErrInvalidToken
	}

	payload, signature := parts[0], parts[1]
	if !VerifyToken(payload, signature, secret) {
		return SessionClaims{}, ErrInvalidToken
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return SessionClaims{}, ErrInvalidToken
	}

	var claims SessionClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return SessionClaims{}, ErrInvalidToken
	}

	if time.Now().Unix() > claims.ExpiresAt {
		return SessionClaims{}, ErrExpiredToken
	}
	claims.Role = NormalizeRole(claims.Username, claims.Role)

	return claims, nil
}

func NormalizeRole(username, role string) string {
	role = strings.TrimSpace(strings.ToLower(role))
	switch role {
	case RoleAdmin, RoleGuest:
		return role
	}

	username = strings.TrimSpace(strings.ToLower(username))
	if username == RoleGuest {
		return RoleGuest
	}
	return RoleGuest
}

func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hashed), nil
}

func VerifyPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
