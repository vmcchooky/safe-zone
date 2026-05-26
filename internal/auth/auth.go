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
)

var (
	ErrInvalidToken = errors.New("invalid session token")
	ErrExpiredToken = errors.New("session token expired")
)

// SessionClaims represents the payload stored inside the signed session cookie.
type SessionClaims struct {
	Username  string `json:"username"`
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
	claims := SessionClaims{
		Username:  username,
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
	parts := strings.Split(cookieVal, ".")
	if len(parts) != 2 {
		return "", ErrInvalidToken
	}

	payload, signature := parts[0], parts[1]
	if !VerifyToken(payload, signature, secret) {
		return "", ErrInvalidToken
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", ErrInvalidToken
	}

	var claims SessionClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return "", ErrInvalidToken
	}

	if time.Now().Unix() > claims.ExpiresAt {
		return "", ErrExpiredToken
	}

	return claims.Username, nil
}
