package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Claims struct {
	Subject       string   `json:"sub"`
	TenantID      string   `json:"tenant_id"`
	Email         string   `json:"email"`
	Roles         []string `json:"roles"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
}

type TokenRequest struct {
	UserID   string   `json:"user_id"`
	TenantID string   `json:"tenant_id"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	TenantID    string `json:"tenant_id"`
}

type Service struct {
	secretKey []byte
}

func NewService(secret string) *Service {
	return &Service{
		secretKey: []byte(secret),
	}
}

func (s *Service) SignToken(c Claims) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	unsignedToken := fmt.Sprintf("%s.%s", header, payload)
	h := hmac.New(sha256.New, s.secretKey)
	h.Write([]byte(unsignedToken))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s", unsignedToken, sig), nil
}

func (s *Service) VerifyToken(tokenStr string) (*Claims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed jwt")
	}

	unsignedToken := fmt.Sprintf("%s.%s", parts[0], parts[1])
	h := hmac.New(sha256.New, s.secretKey)
	h.Write([]byte(unsignedToken))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, errors.New("invalid signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid payload encoding")
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errors.New("invalid claims format")
	}

	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

func (s *Service) HandleIssueToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	now := time.Now()
	claims := Claims{
		Subject:   req.UserID,
		TenantID:  req.TenantID,
		Email:     req.Email,
		Roles:     req.Roles,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(2 * time.Hour).Unix(),
	}

	tokenStr, err := s.SignToken(claims)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to sign token"})
		return
	}

	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: tokenStr,
		TokenType:   "Bearer",
		ExpiresIn:   7200,
		TenantID:    req.TenantID,
	})
}

func (s *Service) HandleValidateToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authHeader := r.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing token"})
		return
	}

	claims, err := s.VerifyToken(tokenStr)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "valid": "false"})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"valid":  true,
		"claims": claims,
	})
}
