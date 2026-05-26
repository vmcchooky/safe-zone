package auth

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestAuthSessionLifecycle(t *testing.T) {
	// Generate random secret key
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("failed to read random secret: %v", err)
	}

	username := "admin"

	t.Run("Generate & Verify Valid Cookie", func(t *testing.T) {
		token, err := GenerateSessionCookieValue(username, 5*time.Minute, secret)
		if err != nil {
			t.Fatalf("failed to generate session cookie: %v", err)
		}

		verifiedUser, err := VerifySessionCookieValue(token, secret)
		if err != nil {
			t.Fatalf("failed to verify valid session cookie: %v", err)
		}

		if verifiedUser != username {
			t.Errorf("expected username %q, got %q", username, verifiedUser)
		}
	})

	t.Run("Expired Token Detection", func(t *testing.T) {
		// Generate an expired token (expires 1 second ago)
		token, err := GenerateSessionCookieValue(username, -1*time.Second, secret)
		if err != nil {
			t.Fatalf("failed to generate session cookie: %v", err)
		}

		_, err = VerifySessionCookieValue(token, secret)
		if err != ErrExpiredToken {
			t.Errorf("expected error %v, got %v", ErrExpiredToken, err)
		}
	})

	t.Run("Tampered Signature Detection", func(t *testing.T) {
		token, err := GenerateSessionCookieValue(username, 5*time.Minute, secret)
		if err != nil {
			t.Fatalf("failed to generate session cookie: %v", err)
		}

		// Tamper with the signature (change the last character)
		tamperedToken := token[:len(token)-1] + "X"

		_, err = VerifySessionCookieValue(tamperedToken, secret)
		if err != ErrInvalidToken {
			t.Errorf("expected error %v, got %v", ErrInvalidToken, err)
		}
	})

	t.Run("Tampered Payload Detection", func(t *testing.T) {
		token, err := GenerateSessionCookieValue(username, 5*time.Minute, secret)
		if err != nil {
			t.Fatalf("failed to generate session cookie: %v", err)
		}

		// Tamper with the payload (insert "X" in base64 prefix before dot)
		dotIdx := len(token) / 2
		tamperedToken := token[:dotIdx] + "X" + token[dotIdx:]

		_, err = VerifySessionCookieValue(tamperedToken, secret)
		if err != ErrInvalidToken {
			t.Errorf("expected error %v, got %v", ErrInvalidToken, err)
		}
	})

	t.Run("Generate Secure Random String", func(t *testing.T) {
		str, err := GenerateSecureRandomString(16)
		if err != nil {
			t.Fatalf("failed to generate secure string: %v", err)
		}

		if len(str) != 32 { // 16 bytes encoded to hex is 32 characters
			t.Errorf("expected length 32, got %d", len(str))
		}
	})
}
