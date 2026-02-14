package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenIssuer implements ports.TokenIssuer with RS256.
type TokenIssuer struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
}

type accessClaims struct {
	jwt.RegisteredClaims
	ProjectID   string `json:"project_id"`
	UserID      string `json:"user_id"`
	OrgID       string `json:"org_id,omitempty"`   // optional; present when token is org-scoped
	Role        string `json:"role,omitempty"`    // optional; member role in org
	MFAPending  bool   `json:"mfa_pending,omitempty"`
}

func NewTokenIssuer(privateKey *rsa.PrivateKey, issuer, audience string) *TokenIssuer {
	return &TokenIssuer{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		issuer:     issuer,
		audience:   audience,
	}
}

func (t *TokenIssuer) IssueAccessToken(projectID, userID string, expiresInSeconds int64) (string, error) {
	return t.issueAccessToken(projectID, userID, "", "", expiresInSeconds)
}

func (t *TokenIssuer) IssueAccessTokenWithOrg(projectID, userID, orgID, role string, expiresInSeconds int64) (string, error) {
	return t.issueAccessToken(projectID, userID, orgID, role, expiresInSeconds)
}

func (t *TokenIssuer) issueAccessToken(projectID, userID, orgID, role string, expiresInSeconds int64) (string, error) {
	now := time.Now()
	claims := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Audience:  jwt.ClaimStrings{t.audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expiresInSeconds) * time.Second)),
		},
		ProjectID: projectID,
		UserID:    userID,
		OrgID:     orgID,
		Role:      role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(t.privateKey)
}

func (t *TokenIssuer) ValidateAccessToken(tokenString string) (projectID, userID, orgID, role string, err error) {
	projectID, userID, orgID, role, mfaPending, err := t.parseClaims(tokenString)
	if err != nil {
		return "", "", "", "", err
	}
	if mfaPending {
		return "", "", "", "", errors.New("token is MFA pending; complete MFA first")
	}
	return projectID, userID, orgID, role, nil
}

func (t *TokenIssuer) IssueMFAPendingToken(projectID, userID string, expiresInSeconds int64) (string, error) {
	now := time.Now()
	claims := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Audience:  jwt.ClaimStrings{t.audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expiresInSeconds) * time.Second)),
		},
		ProjectID:  projectID,
		UserID:     userID,
		MFAPending: true,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(t.privateKey)
}

func (t *TokenIssuer) ValidateMFAPendingToken(tokenString string) (projectID, userID string, err error) {
	projectID, userID, _, _, mfaPending, err := t.parseClaims(tokenString)
	if err != nil {
		return "", "", err
	}
	if !mfaPending {
		return "", "", errors.New("not an MFA pending token")
	}
	return projectID, userID, nil
}

func (t *TokenIssuer) parseClaims(tokenString string) (projectID, userID, orgID, role string, mfaPending bool, err error) {
	token, err := jwt.ParseWithClaims(tokenString, &accessClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return t.publicKey, nil
	})
	if err != nil {
		return "", "", "", "", false, err
	}
	claims, ok := token.Claims.(*accessClaims)
	if !ok || !token.Valid {
		return "", "", "", "", false, errors.New("invalid token claims")
	}
	return claims.ProjectID, claims.UserID, claims.OrgID, claims.Role, claims.MFAPending, nil
}
