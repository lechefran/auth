package auth

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lechefran/auth/password"
)

func TestRegisterCreatesUserAndPasswordHash(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	result, err := service.Register(context.Background(), RegisterRequest{
		Email:       " USER@example.COM ",
		DisplayName: " Test User ",
		Password:    []byte("correct horse battery staple"),
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if result.User.Email != "user@example.com" {
		t.Fatalf("Register() email = %q, want normalized email", result.User.Email)
	}
	if len(store.passwordHashes[result.User.ID]) == 0 {
		t.Fatal("Register() did not store password hash")
	}
	if store.auditCount(AuditEventUserRegistered) != 1 {
		t.Fatal("Register() did not record user registration audit event")
	}
}

func TestLoginCreatesSessionAndRefreshToken(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	registered, err := service.Register(context.Background(), RegisterRequest{
		Email:    "user@example.com",
		Password: []byte("correct horse battery staple"),
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	result, err := service.Login(context.Background(), LoginRequest{
		Email:    "USER@example.com",
		Password: []byte("correct horse battery staple"),
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if result.User.ID != registered.User.ID {
		t.Fatalf("Login() user ID = %q, want %q", result.User.ID, registered.User.ID)
	}
	if result.Session.UserID != registered.User.ID {
		t.Fatalf("Login() session user ID = %q, want %q", result.Session.UserID, registered.User.ID)
	}
	if result.RefreshToken == "" {
		t.Fatal("Login() returned empty refresh token")
	}
	if len(store.tokens) != 1 {
		t.Fatalf("Login() stored %d refresh tokens, want 1", len(store.tokens))
	}
	if store.auditCount(AuditEventLoginSucceeded) != 1 {
		t.Fatal("Login() did not record login success audit event")
	}
}

func TestLoginRejectsWrongPasswordWithoutLeakingAccountState(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	if _, err := service.Register(context.Background(), RegisterRequest{
		Email:    "user@example.com",
		Password: []byte("correct horse battery staple"),
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	_, err := service.Login(context.Background(), LoginRequest{
		Email:    "user@example.com",
		Password: []byte("wrong password"),
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want ErrInvalidCredentials", err)
	}
	if store.auditCount(AuditEventLoginFailed) != 1 {
		t.Fatal("Login() did not record login failure audit event")
	}
}

func TestLoginRejectsUnknownEmailLikeWrongPassword(t *testing.T) {
	t.Parallel()

	service, _ := newTestService(t)
	_, err := service.Login(context.Background(), LoginRequest{
		Email:    "missing@example.com",
		Password: []byte("wrong password"),
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want ErrInvalidCredentials", err)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	login := registerAndLogin(t, service)

	if err := service.Logout(context.Background(), LogoutRequest{SessionID: login.Session.ID}); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	session := store.sessions[login.Session.ID]
	if session.RevokedAt == nil {
		t.Fatal("Logout() did not revoke session")
	}
	if store.auditCount(AuditEventLogoutSucceeded) != 1 {
		t.Fatal("Logout() did not record logout audit event")
	}
}

func TestRefreshSessionRotatesRefreshToken(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	login := registerAndLogin(t, service)

	result, err := service.RefreshSession(context.Background(), RefreshSessionRequest{
		RefreshToken: login.RefreshToken,
	})
	if err != nil {
		t.Fatalf("RefreshSession() error = %v", err)
	}

	if result.RefreshToken == "" || result.RefreshToken == login.RefreshToken {
		t.Fatal("RefreshSession() did not return replacement refresh token")
	}
	if result.Session.UserID != login.User.ID {
		t.Fatalf("RefreshSession() session user ID = %q, want %q", result.Session.UserID, login.User.ID)
	}

	revokedCount := 0
	for _, token := range store.tokens {
		if token.RevokedAt != nil {
			revokedCount++
		}
	}
	if revokedCount != 1 {
		t.Fatalf("RefreshSession() revoked %d tokens, want 1", revokedCount)
	}
	if store.auditCount(AuditEventTokenRefreshed) != 1 {
		t.Fatal("RefreshSession() did not record token refresh audit event")
	}
}

func TestRefreshSessionRejectsReplayAndRevokesFamily(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	login := registerAndLogin(t, service)
	if _, err := service.RefreshSession(context.Background(), RefreshSessionRequest{
		RefreshToken: login.RefreshToken,
	}); err != nil {
		t.Fatalf("RefreshSession() error = %v", err)
	}

	_, err := service.RefreshSession(context.Background(), RefreshSessionRequest{
		RefreshToken: login.RefreshToken,
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("RefreshSession() replay error = %v, want ErrInvalidCredentials", err)
	}

	for _, token := range store.tokens {
		if token.RevokedAt == nil {
			t.Fatal("RefreshSession() replay did not revoke token family")
		}
	}
}

func TestChangePasswordUpdatesHashAndRevokesSessionsAndTokens(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	login := registerAndLogin(t, service)
	oldHash := append([]byte(nil), store.passwordHashes[login.User.ID]...)

	err := service.ChangePassword(context.Background(), ChangePasswordRequest{
		UserID:          login.User.ID,
		CurrentPassword: []byte("correct horse battery staple"),
		NewPassword:     []byte("new correct horse battery staple"),
	})
	if err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	if bytes.Equal(oldHash, store.passwordHashes[login.User.ID]) {
		t.Fatal("ChangePassword() did not update password hash")
	}
	if store.sessions[login.Session.ID].RevokedAt == nil {
		t.Fatal("ChangePassword() did not revoke sessions")
	}
	for _, token := range store.tokens {
		if token.RevokedAt == nil {
			t.Fatal("ChangePassword() did not revoke refresh tokens")
		}
	}
	if store.auditCount(AuditEventPasswordChanged) != 1 {
		t.Fatal("ChangePassword() did not record password change audit event")
	}
}

func TestWorkflowRequiresStores(t *testing.T) {
	t.Parallel()

	service, err := New(Config{Issuer: "test-issuer"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = service.Login(context.Background(), LoginRequest{
		Email:    "user@example.com",
		Password: []byte("password"),
	})
	if !errors.Is(err, ErrMissingStore) {
		t.Fatalf("Login() error = %v, want ErrMissingStore", err)
	}
}

func registerAndLogin(t *testing.T, service *Service) LoginResult {
	t.Helper()

	if _, err := service.Register(context.Background(), RegisterRequest{
		Email:    "user@example.com",
		Password: []byte("correct horse battery staple"),
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	login, err := service.Login(context.Background(), LoginRequest{
		Email:    "user@example.com",
		Password: []byte("correct horse battery staple"),
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	return login
}

func newTestService(t *testing.T) (*Service, *memoryStore) {
	t.Helper()

	store := newMemoryStore()
	service, err := New(Config{
		Issuer:      "test-issuer",
		Clock:       fixedClock{now: time.Date(2026, 6, 3, 16, 0, 0, 0, time.UTC)},
		Passwords:   password.Argon2id(),
		Users:       store,
		Credentials: store,
		Sessions:    store,
		Tokens:      store,
		Audit:       store,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return service, store
}

type memoryStore struct {
	users          map[string]User
	usersByEmail   map[string]string
	passwordHashes map[string][]byte
	sessions       map[string]Session
	tokens         map[string]Token
	tokensByHash   map[string]string
	auditEvents    []AuditEvent
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		users:          make(map[string]User),
		usersByEmail:   make(map[string]string),
		passwordHashes: make(map[string][]byte),
		sessions:       make(map[string]Session),
		tokens:         make(map[string]Token),
		tokensByHash:   make(map[string]string),
	}
}

func (s *memoryStore) CreateUser(_ context.Context, user User) error {
	if _, ok := s.users[user.ID]; ok {
		return ErrAlreadyExists
	}
	if _, ok := s.usersByEmail[user.Email]; ok {
		return ErrAlreadyExists
	}
	s.users[user.ID] = user
	s.usersByEmail[user.Email] = user.ID
	return nil
}

func (s *memoryStore) GetUserByID(_ context.Context, userID string) (User, error) {
	user, ok := s.users[userID]
	if !ok {
		return User{}, ErrNotFound
	}
	return user, nil
}

func (s *memoryStore) GetUserByEmail(_ context.Context, email string) (User, error) {
	userID, ok := s.usersByEmail[email]
	if !ok {
		return User{}, ErrNotFound
	}
	return s.GetUserByID(context.Background(), userID)
}

func (s *memoryStore) UpdateUser(_ context.Context, user User) error {
	if _, ok := s.users[user.ID]; !ok {
		return ErrNotFound
	}
	if existingID, ok := s.usersByEmail[user.Email]; ok && existingID != user.ID {
		return ErrConflict
	}
	s.users[user.ID] = user
	s.usersByEmail[user.Email] = user.ID
	return nil
}

func (s *memoryStore) SetPasswordHash(_ context.Context, userID string, passwordHash []byte) error {
	if _, ok := s.users[userID]; !ok {
		return ErrNotFound
	}
	s.passwordHashes[userID] = append([]byte(nil), passwordHash...)
	return nil
}

func (s *memoryStore) GetPasswordHash(_ context.Context, userID string) ([]byte, error) {
	hash, ok := s.passwordHashes[userID]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), hash...), nil
}

func (s *memoryStore) DeletePasswordHash(_ context.Context, userID string) error {
	if _, ok := s.passwordHashes[userID]; !ok {
		return ErrNotFound
	}
	delete(s.passwordHashes, userID)
	return nil
}

func (s *memoryStore) CreateSession(_ context.Context, session Session) error {
	if _, ok := s.sessions[session.ID]; ok {
		return ErrAlreadyExists
	}
	s.sessions[session.ID] = session
	return nil
}

func (s *memoryStore) GetSessionByID(_ context.Context, sessionID string) (Session, error) {
	session, ok := s.sessions[sessionID]
	if !ok {
		return Session{}, ErrNotFound
	}
	return session, nil
}

func (s *memoryStore) ListSessionsByUserID(_ context.Context, userID string) ([]Session, error) {
	var sessions []Session
	for _, session := range s.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

func (s *memoryStore) RevokeSession(_ context.Context, sessionID string, revokedAt time.Time) error {
	session, ok := s.sessions[sessionID]
	if !ok {
		return ErrNotFound
	}
	if session.RevokedAt != nil {
		return ErrInvalidState
	}
	session.RevokedAt = &revokedAt
	s.sessions[sessionID] = session
	return nil
}

func (s *memoryStore) RevokeUserSessions(_ context.Context, userID string, revokedAt time.Time) error {
	for id, session := range s.sessions {
		if session.UserID == userID && session.RevokedAt == nil {
			session.RevokedAt = &revokedAt
			s.sessions[id] = session
		}
	}
	return nil
}

func (s *memoryStore) CreateToken(_ context.Context, token Token) error {
	if _, ok := s.tokens[token.ID]; ok {
		return ErrAlreadyExists
	}
	hashKey := string(token.Hash)
	if _, ok := s.tokensByHash[hashKey]; ok {
		return ErrAlreadyExists
	}
	s.tokens[token.ID] = token
	s.tokensByHash[hashKey] = token.ID
	return nil
}

func (s *memoryStore) GetTokenByID(_ context.Context, tokenID string) (Token, error) {
	token, ok := s.tokens[tokenID]
	if !ok {
		return Token{}, ErrNotFound
	}
	return token, nil
}

func (s *memoryStore) GetTokenByHash(_ context.Context, tokenHash []byte) (Token, error) {
	tokenID, ok := s.tokensByHash[string(tokenHash)]
	if !ok {
		return Token{}, ErrNotFound
	}
	return s.GetTokenByID(context.Background(), tokenID)
}

func (s *memoryStore) RevokeToken(_ context.Context, tokenID string, revokedAt time.Time) error {
	token, ok := s.tokens[tokenID]
	if !ok {
		return ErrNotFound
	}
	if token.RevokedAt != nil {
		return ErrInvalidState
	}
	token.RevokedAt = &revokedAt
	s.tokens[tokenID] = token
	return nil
}

func (s *memoryStore) RotateToken(_ context.Context, currentHash []byte, replacement Token, rotatedAt time.Time) (Token, error) {
	current, err := s.GetTokenByHash(context.Background(), currentHash)
	if err != nil {
		return Token{}, err
	}
	if current.RevokedAt != nil || current.IsExpired(rotatedAt) {
		return Token{}, ErrInvalidState
	}
	if _, ok := s.tokens[replacement.ID]; ok {
		return Token{}, ErrAlreadyExists
	}
	if _, ok := s.tokensByHash[string(replacement.Hash)]; ok {
		return Token{}, ErrAlreadyExists
	}

	current.RevokedAt = &rotatedAt
	s.tokens[current.ID] = current
	s.tokens[replacement.ID] = replacement
	s.tokensByHash[string(replacement.Hash)] = replacement.ID
	return current, nil
}

func (s *memoryStore) RevokeTokenFamily(_ context.Context, familyID string, revokedAt time.Time) error {
	for id, token := range s.tokens {
		if token.FamilyID == familyID && token.RevokedAt == nil {
			token.RevokedAt = &revokedAt
			s.tokens[id] = token
		}
	}
	return nil
}

func (s *memoryStore) RecordAuditEvent(_ context.Context, event AuditEvent) error {
	s.auditEvents = append(s.auditEvents, event)
	return nil
}

func (s *memoryStore) auditCount(eventType AuditEventType) int {
	count := 0
	for _, event := range s.auditEvents {
		if event.Type == eventType {
			count++
		}
	}
	return count
}
