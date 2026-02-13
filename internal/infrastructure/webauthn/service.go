package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
)

const sessionTTL = 5 * time.Minute

type sessionEntry struct {
	data      webauthn.SessionData
	projectID string
	userID    string // for register; empty for discoverable login
	expires   time.Time
}

// SessionStore stores WebAuthn session data in memory (session ID -> entry).
type SessionStore struct {
	mu   sync.RWMutex
	data map[string]*sessionEntry
}

func NewSessionStore() *SessionStore {
	s := &SessionStore{data: make(map[string]*sessionEntry)}
	go s.cleanup()
	return s
}

func (s *SessionStore) Save(sessionID string, data webauthn.SessionData, projectID, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[sessionID] = &sessionEntry{data: data, projectID: projectID, userID: userID, expires: time.Now().Add(sessionTTL)}
}

func (s *SessionStore) Load(sessionID string) (data webauthn.SessionData, projectID, userID string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.data[sessionID]
	if e == nil || time.Now().After(e.expires) {
		delete(s.data, sessionID)
		return webauthn.SessionData{}, "", "", false
	}
	return e.data, e.projectID, e.userID, true
}

func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, sessionID)
}

func (s *SessionStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, e := range s.data {
			if now.After(e.expires) {
				delete(s.data, id)
			}
		}
		s.mu.Unlock()
	}
}

// nonceUser implements webauthn.User for a domain user + credentials from store.
type nonceUser struct {
	domainUser *domain.User
	creds      []webauthn.Credential
}

func (u *nonceUser) WebAuthnID() []byte                    { return u.domainUser.ID.UUID[:] }
func (u *nonceUser) WebAuthnName() string                  { return u.domainUser.Email }
func (u *nonceUser) WebAuthnDisplayName() string            { return u.domainUser.Email }
func (u *nonceUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// Service wraps go-webauthn and provides registration/login with session and storage.
type Service struct {
	wa         *webauthn.WebAuthn
	credStore  ports.WebAuthnCredentialStore
	userRepo   ports.UserRepository
	sessions   *SessionStore
}

// NewService creates a WebAuthn service.
func NewService(cfg *Config, credStore ports.WebAuthnCredentialStore, userRepo ports.UserRepository) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, err
	}
	return &Service{
		wa:        wa,
		credStore: credStore,
		userRepo:  userRepo,
		sessions:  NewSessionStore(),
	}, nil
}

// Config for WebAuthn (from app config).
type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
	Timeout       int
}

// BeginRegistration returns creation options and a session ID. Caller must be authenticated (user + project).
func (s *Service) BeginRegistration(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) (creationJSON []byte, sessionID string, err error) {
	user, err := s.userRepo.GetByID(ctx, projectID, userID)
	if err != nil || user == nil {
		return nil, "", err
	}
	rows, err := s.credStore.ListByUser(ctx, projectID, userID)
	if err != nil {
		return nil, "", err
	}
	creds := make([]webauthn.Credential, len(rows))
	for i, row := range rows {
		creds[i] = webauthn.Credential{
			ID:        row.ID,
			PublicKey: row.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: row.SignCount,
			},
		}
	}
	u := &nonceUser{domainUser: user, creds: creds}
	creation, session, err := s.wa.BeginRegistration(u, webauthn.WithExclusions(webauthn.Credentials(creds).CredentialDescriptors()))
	if err != nil {
		return nil, "", err
	}
	sid := genSessionID()
	s.sessions.Save(sid, *session, projectID.String(), userID.String())
	creationJSON, _ = json.Marshal(creation)
	return creationJSON, sid, nil
}

// FinishRegistration consumes the credential response and stores the new credential. Session ID in header or body.
func (s *Service) FinishRegistration(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, sessionID string, body io.Reader) error {
	session, projID, uid, ok := s.sessions.Load(sessionID)
	if !ok || projID != projectID.String() || uid != userID.String() {
		return ErrInvalidSession
	}
	defer s.sessions.Delete(sessionID)
	user, err := s.userRepo.GetByID(ctx, projectID, userID)
	if err != nil || user == nil {
		return err
	}
	rows, _ := s.credStore.ListByUser(ctx, projectID, userID)
	creds := make([]webauthn.Credential, len(rows))
	for i, row := range rows {
		creds[i] = webauthn.Credential{ID: row.ID, PublicKey: row.PublicKey, Authenticator: webauthn.Authenticator{SignCount: row.SignCount}}
	}
	u := &nonceUser{domainUser: user, creds: creds}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "", body)
	req.Header.Set("Content-Type", "application/json")
	cred, err := s.wa.FinishRegistration(u, session, req)
	if err != nil {
		return err
	}
	return s.credStore.Create(ctx, projectID, userID, cred.ID, cred.PublicKey, cred.Authenticator.SignCount)
}

// BeginLogin returns assertion options and session ID (discoverable/passkey login). Requires project.
func (s *Service) BeginLogin(ctx context.Context, projectID domain.ProjectID) (assertionJSON []byte, sessionID string, err error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", err
	}
	sid := genSessionID()
	s.sessions.Save(sid, *session, projectID.String(), "")
	assertionJSON, _ = json.Marshal(assertion)
	return assertionJSON, sid, nil
}

// FinishLogin validates the assertion and returns project ID and user ID. Updates credential sign count.
func (s *Service) FinishLogin(ctx context.Context, sessionID string, body io.Reader) (projectID domain.ProjectID, userID domain.UserID, err error) {
	session, projectIDStr, _, ok := s.sessions.Load(sessionID)
	if !ok || projectIDStr == "" {
		return domain.ProjectID{}, domain.UserID{}, ErrInvalidSession
	}
	defer s.sessions.Delete(sessionID)
	parsed, err := uuid.Parse(projectIDStr)
	if err != nil {
		return domain.ProjectID{}, domain.UserID{}, err
	}
	pid := domain.NewProjectID(parsed)
	loadUser := func(rawID, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) != 16 {
			return nil, ErrInvalidSession
		}
		var id uuid.UUID
		copy(id[:], userHandle)
		uid := domain.NewUserID(id)
		user, err := s.userRepo.GetByID(ctx, pid, uid)
		if err != nil || user == nil {
			return nil, err
		}
		rows, err := s.credStore.ListByUser(ctx, pid, uid)
		if err != nil {
			return nil, err
		}
		creds := make([]webauthn.Credential, len(rows))
		for i, row := range rows {
			creds[i] = webauthn.Credential{ID: row.ID, PublicKey: row.PublicKey, Authenticator: webauthn.Authenticator{SignCount: row.SignCount}}
		}
		return &nonceUser{domainUser: user, creds: creds}, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "", body)
	req.Header.Set("Content-Type", "application/json")
	validatedUser, validatedCred, err := s.wa.FinishPasskeyLogin(loadUser, session, req)
	if err != nil {
		return domain.ProjectID{}, domain.UserID{}, err
	}
	nu, ok := validatedUser.(*nonceUser)
	if !ok {
		return domain.ProjectID{}, domain.UserID{}, ErrInvalidSession
	}
	_ = s.credStore.UpdateSignCount(ctx, pid, validatedCred.ID, validatedCred.Authenticator.SignCount)
	return pid, nu.domainUser.ID, nil
}

func genSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var ErrInvalidSession = errors.New("invalid or expired webauthn session")
