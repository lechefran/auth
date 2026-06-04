package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lechefran/auth/token"
)

// RegisterRequest contains the information needed to create a password-backed
// user account.
type RegisterRequest struct {
	Email       string
	DisplayName string
	Password    []byte
}

// RegisterResult contains the created user.
type RegisterResult struct {
	User User
}

// LoginRequest contains password login credentials.
type LoginRequest struct {
	Email    string
	Password []byte
}

// LoginResult contains the authenticated user, new session, and refresh token.
type LoginResult struct {
	User         User
	Session      Session
	RefreshToken string
}

// LogoutRequest identifies a session to revoke.
type LogoutRequest struct {
	SessionID string
}

// RefreshSessionRequest contains a refresh token to rotate.
type RefreshSessionRequest struct {
	RefreshToken string
}

// RefreshSessionResult contains the refreshed session and replacement refresh
// token. The previous refresh token must be discarded by the caller.
type RefreshSessionResult struct {
	Session      Session
	RefreshToken string
}

// ChangePasswordRequest changes a user's password after verifying the current
// password.
type ChangePasswordRequest struct {
	UserID          string
	CurrentPassword []byte
	NewPassword     []byte
}

// Register creates a password-backed user account.
func (s *Service) Register(ctx context.Context, req RegisterRequest) (RegisterResult, error) {
	email := normalizeEmail(req.Email)
	if email == "" || len(req.Password) == 0 {
		return RegisterResult{}, ErrInvalidRequest
	}
	if err := s.requireStores(s.cfg.Users, s.cfg.Credentials); err != nil {
		return RegisterResult{}, err
	}

	now := s.cfg.Clock.Now()
	userID, err := token.GenerateSessionID()
	if err != nil {
		return RegisterResult{}, fmt.Errorf("generate user id: %w", err)
	}

	hash, err := s.cfg.Passwords.Hash(req.Password)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("hash password: %w", err)
	}

	user := User{
		ID:          userID,
		Email:       email,
		DisplayName: strings.TrimSpace(req.DisplayName),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.cfg.Users.CreateUser(ctx, user); err != nil {
		return RegisterResult{}, err
	}
	if err := s.cfg.Credentials.SetPasswordHash(ctx, user.ID, []byte(hash)); err != nil {
		return RegisterResult{}, err
	}
	if err := s.recordAudit(ctx, AuditEventUserRegistered, "", user.ID, "", ""); err != nil {
		return RegisterResult{}, err
	}

	return RegisterResult{User: user}, nil
}

// Login verifies a password and creates a session plus refresh token.
func (s *Service) Login(ctx context.Context, req LoginRequest) (LoginResult, error) {
	email := normalizeEmail(req.Email)
	if email == "" || len(req.Password) == 0 {
		return LoginResult{}, ErrInvalidRequest
	}
	if err := s.requireStores(s.cfg.Users, s.cfg.Credentials, s.cfg.Sessions, s.cfg.Tokens); err != nil {
		return LoginResult{}, err
	}

	user, err := s.cfg.Users.GetUserByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		_ = s.recordAudit(ctx, AuditEventLoginFailed, "", "", "", "")
		return LoginResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return LoginResult{}, err
	}
	if user.IsDisabled() {
		_ = s.recordAudit(ctx, AuditEventLoginFailed, user.ID, user.ID, "", "")
		return LoginResult{}, ErrDisabledUser
	}

	storedHash, err := s.cfg.Credentials.GetPasswordHash(ctx, user.ID)
	if errors.Is(err, ErrNotFound) {
		_ = s.recordAudit(ctx, AuditEventLoginFailed, user.ID, user.ID, "", "")
		return LoginResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return LoginResult{}, err
	}

	matched, needsRehash, err := s.cfg.Passwords.Verify(string(storedHash), req.Password)
	if err != nil {
		return LoginResult{}, fmt.Errorf("verify password: %w", err)
	}
	if !matched {
		_ = s.recordAudit(ctx, AuditEventLoginFailed, user.ID, user.ID, "", "")
		return LoginResult{}, ErrInvalidCredentials
	}
	if needsRehash {
		hash, err := s.cfg.Passwords.Hash(req.Password)
		if err != nil {
			return LoginResult{}, fmt.Errorf("rehash password: %w", err)
		}
		if err := s.cfg.Credentials.SetPasswordHash(ctx, user.ID, []byte(hash)); err != nil {
			return LoginResult{}, err
		}
	}

	session, refreshToken, refreshRecord, err := s.createSessionAndRefreshToken(ctx, user.ID, "")
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.recordAudit(ctx, AuditEventLoginSucceeded, user.ID, user.ID, session.ID, refreshRecord.ID); err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		User:         user,
		Session:      session,
		RefreshToken: refreshToken,
	}, nil
}

// Logout revokes a session.
func (s *Service) Logout(ctx context.Context, req LogoutRequest) error {
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		return ErrInvalidRequest
	}
	if err := s.requireStores(s.cfg.Sessions); err != nil {
		return err
	}

	now := s.cfg.Clock.Now()
	if err := s.cfg.Sessions.RevokeSession(ctx, sessionID, now); err != nil {
		return err
	}
	return s.recordAudit(ctx, AuditEventLogoutSucceeded, "", "", sessionID, "")
}

// RefreshSession rotates a refresh token and creates a replacement session.
func (s *Service) RefreshSession(ctx context.Context, req RefreshSessionRequest) (RefreshSessionResult, error) {
	refreshToken := strings.TrimSpace(req.RefreshToken)
	if refreshToken == "" {
		return RefreshSessionResult{}, ErrInvalidRequest
	}
	if err := s.requireStores(s.cfg.Sessions, s.cfg.Tokens); err != nil {
		return RefreshSessionResult{}, err
	}

	currentHash, err := token.LookupHash(refreshToken)
	if err != nil {
		return RefreshSessionResult{}, err
	}
	now := s.cfg.Clock.Now()

	current, err := s.cfg.Tokens.GetTokenByHash(ctx, currentHash)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidState) {
		return RefreshSessionResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return RefreshSessionResult{}, err
	}
	if current.IsRevoked() {
		_ = s.cfg.Tokens.RevokeTokenFamily(ctx, current.FamilyID, now)
		return RefreshSessionResult{}, ErrInvalidCredentials
	}
	if current.IsExpired(now) || current.Issuer != s.cfg.Issuer || current.Subject == "" {
		return RefreshSessionResult{}, ErrInvalidCredentials
	}

	replacementRaw, replacementRecord, err := s.newRefreshTokenRecord(current.Subject, current.FamilyID, now)
	if err != nil {
		return RefreshSessionResult{}, err
	}
	current, err = s.cfg.Tokens.RotateToken(ctx, currentHash, replacementRecord, now)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidState) {
		return RefreshSessionResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return RefreshSessionResult{}, err
	}

	sessionID, err := token.GenerateSessionID()
	if err != nil {
		return RefreshSessionResult{}, fmt.Errorf("generate session id: %w", err)
	}
	session := Session{
		ID:        sessionID,
		UserID:    current.Subject,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.SessionTTL),
	}
	if err := s.cfg.Sessions.CreateSession(ctx, session); err != nil {
		return RefreshSessionResult{}, err
	}
	if err := s.recordAudit(ctx, AuditEventTokenRefreshed, current.Subject, current.Subject, session.ID, replacementRecord.ID); err != nil {
		return RefreshSessionResult{}, err
	}

	return RefreshSessionResult{
		Session:      session,
		RefreshToken: replacementRaw,
	}, nil
}

// ChangePassword verifies and replaces a user's password hash.
func (s *Service) ChangePassword(ctx context.Context, req ChangePasswordRequest) error {
	userID := strings.TrimSpace(req.UserID)
	if userID == "" || len(req.CurrentPassword) == 0 || len(req.NewPassword) == 0 {
		return ErrInvalidRequest
	}
	if err := s.requireStores(s.cfg.Users, s.cfg.Credentials, s.cfg.Sessions, s.cfg.Tokens); err != nil {
		return err
	}

	user, err := s.cfg.Users.GetUserByID(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return ErrInvalidCredentials
	}
	if err != nil {
		return err
	}
	if user.IsDisabled() {
		return ErrDisabledUser
	}

	storedHash, err := s.cfg.Credentials.GetPasswordHash(ctx, user.ID)
	if errors.Is(err, ErrNotFound) {
		return ErrInvalidCredentials
	}
	if err != nil {
		return err
	}

	matched, _, err := s.cfg.Passwords.Verify(string(storedHash), req.CurrentPassword)
	if err != nil {
		return fmt.Errorf("verify current password: %w", err)
	}
	if !matched {
		return ErrInvalidCredentials
	}

	newHash, err := s.cfg.Passwords.Hash(req.NewPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}
	if err := s.cfg.Credentials.SetPasswordHash(ctx, user.ID, []byte(newHash)); err != nil {
		return err
	}

	now := s.cfg.Clock.Now()
	if err := s.cfg.Sessions.RevokeUserSessions(ctx, user.ID, now); err != nil {
		return err
	}
	if err := s.cfg.Tokens.RevokeTokenFamily(ctx, user.ID, now); err != nil {
		return err
	}
	return s.recordAudit(ctx, AuditEventPasswordChanged, user.ID, user.ID, "", "")
}

func (s *Service) createSessionAndRefreshToken(ctx context.Context, userID string, familyID string) (Session, string, Token, error) {
	now := s.cfg.Clock.Now()

	sessionID, err := token.GenerateSessionID()
	if err != nil {
		return Session{}, "", Token{}, fmt.Errorf("generate session id: %w", err)
	}
	session := Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.SessionTTL),
	}
	if err := s.cfg.Sessions.CreateSession(ctx, session); err != nil {
		return Session{}, "", Token{}, err
	}

	refreshToken, refreshRecord, err := s.newRefreshTokenRecord(userID, familyID, now)
	if err != nil {
		return Session{}, "", Token{}, err
	}
	if err := s.cfg.Tokens.CreateToken(ctx, refreshRecord); err != nil {
		return Session{}, "", Token{}, err
	}

	return session, refreshToken, refreshRecord, nil
}

func (s *Service) newRefreshTokenRecord(userID string, familyID string, now time.Time) (string, Token, error) {
	raw, err := token.GenerateRefreshToken()
	if err != nil {
		return "", Token{}, fmt.Errorf("generate refresh token: %w", err)
	}
	hash, err := token.LookupHash(raw)
	if err != nil {
		return "", Token{}, err
	}
	tokenID, err := token.GenerateSessionID()
	if err != nil {
		return "", Token{}, fmt.Errorf("generate token id: %w", err)
	}
	if familyID == "" {
		familyID = userID
	}
	if familyID == "" {
		familyID, err = token.GenerateSessionID()
		if err != nil {
			return "", Token{}, fmt.Errorf("generate token family id: %w", err)
		}
	}

	return raw, Token{
		ID:        tokenID,
		FamilyID:  familyID,
		Subject:   userID,
		Issuer:    s.cfg.Issuer,
		Hash:      hash,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
	}, nil
}

func (s *Service) recordAudit(ctx context.Context, eventType AuditEventType, actorID string, subjectID string, sessionID string, tokenID string) error {
	if s.cfg.Audit == nil {
		return nil
	}

	eventID, err := token.GenerateSessionID()
	if err != nil {
		return fmt.Errorf("generate audit event id: %w", err)
	}
	return s.cfg.Audit.RecordAuditEvent(ctx, AuditEvent{
		ID:        eventID,
		Type:      eventType,
		ActorID:   actorID,
		SubjectID: subjectID,
		SessionID: sessionID,
		TokenID:   tokenID,
		Occurred:  s.cfg.Clock.Now(),
	})
}

func (s *Service) requireStores(stores ...interface{}) error {
	for _, store := range stores {
		if store == nil {
			return ErrMissingStore
		}
	}
	return nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
