package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	auth "github.com/lechefran/auth"
	_ "modernc.org/sqlite"
)

const maxStoreCursorLength = 1024

// Open opens a SQLite database and verifies connectivity.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Store implements auth stores using SQLite.
type Store struct {
	db *sql.DB
}

// NewStore creates a SQLite store backed by db.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// DeleteData deletes all auth adapter data while keeping the SQLite schema.
func (s *Store) DeleteData(ctx context.Context) error {
	return DeleteData(ctx, s.db)
}

// CreatePrincipal stores a user or group principal.
func (s *Store) CreatePrincipal(ctx context.Context, principal auth.Principal) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_principals(type, id, name, created_at, updated_at, disabled_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		principal.Type,
		principal.ID,
		principal.Name,
		formatTime(principal.CreatedAt),
		formatTime(principal.UpdatedAt),
		formatTimePtr(principal.DisabledAt),
	)
	return mapWriteError(err)
}

// GetPrincipal returns a user or group principal.
func (s *Store) GetPrincipal(ctx context.Context, principalType auth.PrincipalType, principalID string) (auth.Principal, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT type, id, name, created_at, updated_at, disabled_at
		 FROM auth_principals
		 WHERE type = ? AND id = ?`,
		principalType,
		principalID,
	)

	var principal auth.Principal
	var createdAt, updatedAt string
	var disabledAt sql.NullString
	if err := row.Scan(&principal.Type, &principal.ID, &principal.Name, &createdAt, &updatedAt, &disabledAt); err != nil {
		return auth.Principal{}, mapReadError(err)
	}

	var err error
	principal.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return auth.Principal{}, err
	}
	principal.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return auth.Principal{}, err
	}
	principal.DisabledAt, err = parseTimePtr(disabledAt)
	if err != nil {
		return auth.Principal{}, err
	}
	return principal, nil
}

// CreateAPIKey stores API key metadata.
func (s *Store) CreateAPIKey(ctx context.Context, key auth.APIKey) error {
	scopes, err := encodeScopes(key.Scopes)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO auth_api_keys(
			id, issuer, prefix, name, owner_type, owner_id, hash, scopes,
			created_at, expires_at, revoked_at, last_used_at
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID,
		key.Issuer,
		key.Prefix,
		key.Name,
		key.OwnerType,
		key.OwnerID,
		key.Hash,
		scopes,
		formatTime(key.CreatedAt),
		formatTimePtr(key.ExpiresAt),
		formatTimePtr(key.RevokedAt),
		formatTimePtr(key.LastUsedAt),
	)
	return mapWriteError(err)
}

// GetAPIKeyByID returns API key metadata by ID.
func (s *Store) GetAPIKeyByID(ctx context.Context, keyID string) (auth.APIKey, error) {
	return s.getAPIKey(ctx, `WHERE id = ?`, keyID)
}

// GetAPIKeyByPrefix returns API key metadata by public prefix.
func (s *Store) GetAPIKeyByPrefix(ctx context.Context, prefix string) (auth.APIKey, error) {
	return s.getAPIKey(ctx, `WHERE prefix = ?`, prefix)
}

// ListAPIKeys returns a page of keys for a principal.
func (s *Store) ListAPIKeys(ctx context.Context, ownerType auth.PrincipalType, ownerID string, page auth.PageRequest) (auth.Page[auth.APIKey], error) {
	page, err := normalizeStorePage(page)
	if err != nil {
		return auth.Page[auth.APIKey]{}, err
	}
	cursor, err := decodeCursor(page.Cursor)
	if err != nil {
		return auth.Page[auth.APIKey]{}, err
	}

	query := `SELECT id, issuer, prefix, name, owner_type, owner_id, hash, scopes,
			created_at, expires_at, revoked_at, last_used_at
		FROM auth_api_keys
		WHERE owner_type = ? AND owner_id = ?`
	args := []any{ownerType, ownerID}
	if cursor != nil {
		query += ` AND (created_at > ? OR (created_at = ? AND id > ?))`
		args = append(args, cursor.CreatedAt, cursor.CreatedAt, cursor.ID)
	}
	query += ` ORDER BY created_at ASC, id ASC LIMIT ?`
	args = append(args, page.Limit+1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return auth.Page[auth.APIKey]{}, err
	}
	defer rows.Close()

	keys := make([]auth.APIKey, 0, page.Limit+1)
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return auth.Page[auth.APIKey]{}, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return auth.Page[auth.APIKey]{}, err
	}

	result := auth.Page[auth.APIKey]{Items: keys}
	if len(result.Items) > page.Limit {
		result.Items = result.Items[:page.Limit]
		last := result.Items[len(result.Items)-1]
		result.NextCursor, err = encodeCursor(cursorValue{
			CreatedAt: formatTime(last.CreatedAt),
			ID:        last.ID,
		})
		if err != nil {
			return auth.Page[auth.APIKey]{}, err
		}
	}
	return result, nil
}

// RevokeAPIKey marks an API key as revoked.
func (s *Store) RevokeAPIKey(ctx context.Context, keyID string, revokedAt time.Time) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE auth_api_keys
		 SET revoked_at = ?
		 WHERE id = ? AND revoked_at IS NULL`,
		formatTime(revokedAt),
		keyID,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 1 {
		return nil
	}

	key, err := s.GetAPIKeyByID(ctx, keyID)
	if errors.Is(err, auth.ErrNotFound) {
		return auth.ErrNotFound
	}
	if err != nil {
		return err
	}
	if key.RevokedAt != nil {
		return auth.ErrInvalidState
	}
	return auth.ErrConflict
}

// TouchAPIKey records successful use.
func (s *Store) TouchAPIKey(ctx context.Context, keyID string, usedAt time.Time) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE auth_api_keys SET last_used_at = ? WHERE id = ?`,
		formatTime(usedAt),
		keyID,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return auth.ErrNotFound
	}
	return nil
}

// RecordAuditEvent stores an audit event.
func (s *Store) RecordAuditEvent(ctx context.Context, event auth.AuditEvent) error {
	metadata, err := encodeMetadata(event.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO auth_audit_events(
			id, type, actor_id, principal_type, principal_id, api_key_id, occurred, metadata
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID,
		event.Type,
		event.ActorID,
		event.PrincipalType,
		event.PrincipalID,
		event.APIKeyID,
		formatTime(event.Occurred),
		metadata,
	)
	return mapWriteError(err)
}

func (s *Store) getAPIKey(ctx context.Context, where string, args ...any) (auth.APIKey, error) {
	query := `SELECT id, issuer, prefix, name, owner_type, owner_id, hash, scopes,
			created_at, expires_at, revoked_at, last_used_at
		FROM auth_api_keys ` + where
	row := s.db.QueryRowContext(ctx, query, args...)
	return scanAPIKey(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAPIKey(row scanner) (auth.APIKey, error) {
	var key auth.APIKey
	var scopes string
	var createdAt string
	var expiresAt, revokedAt, lastUsedAt sql.NullString
	if err := row.Scan(
		&key.ID,
		&key.Issuer,
		&key.Prefix,
		&key.Name,
		&key.OwnerType,
		&key.OwnerID,
		&key.Hash,
		&scopes,
		&createdAt,
		&expiresAt,
		&revokedAt,
		&lastUsedAt,
	); err != nil {
		return auth.APIKey{}, mapReadError(err)
	}

	var err error
	key.Scopes, err = decodeScopes(scopes)
	if err != nil {
		return auth.APIKey{}, err
	}
	key.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return auth.APIKey{}, err
	}
	key.ExpiresAt, err = parseTimePtr(expiresAt)
	if err != nil {
		return auth.APIKey{}, err
	}
	key.RevokedAt, err = parseTimePtr(revokedAt)
	if err != nil {
		return auth.APIKey{}, err
	}
	key.LastUsedAt, err = parseTimePtr(lastUsedAt)
	if err != nil {
		return auth.APIKey{}, err
	}
	key.Hash = append([]byte(nil), key.Hash...)
	return key, nil
}

type cursorValue struct {
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

func encodeCursor(cursor cursorValue) (string, error) {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeCursor(value string) (*cursorValue, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > maxStoreCursorLength {
		return nil, auth.ErrInvalidRequest
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, auth.ErrInvalidRequest
	}
	var cursor cursorValue
	if err := json.Unmarshal(raw, &cursor); err != nil {
		return nil, auth.ErrInvalidRequest
	}
	if cursor.CreatedAt == "" || cursor.ID == "" {
		return nil, auth.ErrInvalidRequest
	}
	if _, err := parseTime(cursor.CreatedAt); err != nil {
		return nil, auth.ErrInvalidRequest
	}
	return &cursor, nil
}

func normalizeStorePage(page auth.PageRequest) (auth.PageRequest, error) {
	if page.Limit < 0 {
		return auth.PageRequest{}, auth.ErrInvalidRequest
	}
	if page.Limit == 0 {
		page.Limit = auth.DefaultPageLimit
	}
	if page.Limit > auth.MaxPageLimit {
		page.Limit = auth.MaxPageLimit
	}
	return page, nil
}

func encodeScopes(scopes []string) (string, error) {
	if scopes == nil {
		scopes = []string{}
	}
	raw, err := json.Marshal(scopes)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func decodeScopes(value string) ([]string, error) {
	var scopes []string
	if err := json.Unmarshal([]byte(value), &scopes); err != nil {
		return nil, err
	}
	return scopes, nil
}

func encodeMetadata(metadata map[string]string) (string, error) {
	if metadata == nil {
		metadata = map[string]string{}
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func mapReadError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return auth.ErrNotFound
	}
	return err
}

func mapWriteError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "foreign key"):
		return errors.Join(auth.ErrNotFound, err)
	case strings.Contains(lower, "unique") || strings.Contains(lower, "primary key"):
		return errors.Join(auth.ErrAlreadyExists, err)
	case strings.Contains(lower, "constraint"):
		return errors.Join(auth.ErrInvalidState, err)
	default:
		return err
	}
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func formatTimePtr(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: formatTime(*t), Valid: true}
}

func parseTime(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse time %q: %w", value, err)
	}
	return t, nil
}

func parseTimePtr(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	t, err := parseTime(value.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
