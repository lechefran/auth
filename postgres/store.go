package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	auth "github.com/lechefran/auth"
)

const maxStoreCursorLength = 1024

// Store implements auth stores using PostgreSQL.
type Store struct {
	db *sql.DB
}

// NewStore creates a PostgreSQL store backed by db.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// DeleteData deletes all auth adapter data while keeping the PostgreSQL schema.
func (s *Store) DeleteData(ctx context.Context) error {
	return DeleteData(ctx, s.db)
}

// CreatePrincipal stores a user or group principal.
func (s *Store) CreatePrincipal(ctx context.Context, principal auth.Principal) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO auth_principals(type, id, name, created_at, updated_at, disabled_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		principal.Type,
		principal.ID,
		principal.Name,
		principal.CreatedAt.UTC(),
		principal.UpdatedAt.UTC(),
		timePtr(principal.DisabledAt),
	)
	return mapWriteError(err)
}

// GetPrincipal returns a user or group principal.
func (s *Store) GetPrincipal(ctx context.Context, principalType auth.PrincipalType, principalID string) (auth.Principal, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT type, id, name, created_at, updated_at, disabled_at
		 FROM auth_principals
		 WHERE type = $1 AND id = $2`,
		principalType,
		principalID,
	)

	var principal auth.Principal
	var disabledAt sql.NullTime
	if err := row.Scan(
		&principal.Type,
		&principal.ID,
		&principal.Name,
		&principal.CreatedAt,
		&principal.UpdatedAt,
		&disabledAt,
	); err != nil {
		return auth.Principal{}, mapReadError(err)
	}
	principal.CreatedAt = principal.CreatedAt.UTC()
	principal.UpdatedAt = principal.UpdatedAt.UTC()
	principal.DisabledAt = timeFromNull(disabledAt)
	return principal, nil
}

// CreateAPIKey stores API key metadata.
func (s *Store) CreateAPIKey(ctx context.Context, key auth.APIKey) error {
	return createAPIKey(ctx, s.db, key)
}

// CreateAPIKeyWithAudit stores API key metadata and its audit event atomically.
func (s *Store) CreateAPIKeyWithAudit(ctx context.Context, key auth.APIKey, event auth.AuditEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := createAPIKey(ctx, tx, key); err != nil {
		return err
	}
	if err := recordAuditEvent(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func createAPIKey(ctx context.Context, runner sqlRunner, key auth.APIKey) error {
	scopes, err := encodeScopes(key.Scopes)
	if err != nil {
		return err
	}

	_, err = runner.ExecContext(
		ctx,
		`INSERT INTO auth_api_keys(
			id, issuer, prefix, name, owner_type, owner_id, hash, scopes,
			created_at, expires_at, revoked_at, last_used_at
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12)`,
		key.ID,
		key.Issuer,
		key.Prefix,
		key.Name,
		key.OwnerType,
		key.OwnerID,
		key.Hash,
		scopes,
		key.CreatedAt.UTC(),
		timePtr(key.ExpiresAt),
		timePtr(key.RevokedAt),
		timePtr(key.LastUsedAt),
	)
	return mapWriteError(err)
}

// GetAPIKeyByID returns API key metadata by ID.
func (s *Store) GetAPIKeyByID(ctx context.Context, keyID string) (auth.APIKey, error) {
	return s.getAPIKey(ctx, `WHERE id = $1`, keyID)
}

// GetAPIKeyByPrefix returns API key metadata by public prefix.
func (s *Store) GetAPIKeyByPrefix(ctx context.Context, prefix string) (auth.APIKey, error) {
	return s.getAPIKey(ctx, `WHERE prefix = $1`, prefix)
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
		WHERE owner_type = $1 AND owner_id = $2`
	args := []any{ownerType, ownerID}
	if cursor != nil {
		cursorTime, err := parseTimeString(cursor.CreatedAt)
		if err != nil {
			return auth.Page[auth.APIKey]{}, auth.ErrInvalidRequest
		}
		query += ` AND (created_at > $3 OR (created_at = $3 AND id > $4))`
		args = append(args, cursorTime, cursor.ID)
	}
	query += fmt.Sprintf(` ORDER BY created_at ASC, id ASC LIMIT $%d`, len(args)+1)
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
	return revokeAPIKey(ctx, s.db, keyID, revokedAt)
}

// RevokeAPIKeyWithAudit reads and revokes an API key, then stores its audit event atomically.
func (s *Store) RevokeAPIKeyWithAudit(ctx context.Context, keyID string, revokedAt time.Time, event auth.AuditEvent) (auth.APIKey, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.APIKey{}, err
	}
	defer tx.Rollback()

	key, err := getAPIKey(ctx, tx, `WHERE id = $1 FOR UPDATE`, keyID)
	if err != nil {
		return auth.APIKey{}, err
	}
	event.APIKeyID = key.ID
	event.PrincipalType = key.OwnerType
	event.PrincipalID = key.OwnerID
	if err := revokeAPIKey(ctx, tx, keyID, revokedAt); err != nil {
		return auth.APIKey{}, err
	}
	if err := recordAuditEvent(ctx, tx, event); err != nil {
		return auth.APIKey{}, err
	}
	if err := tx.Commit(); err != nil {
		return auth.APIKey{}, err
	}
	key.RevokedAt = &revokedAt
	return key, nil
}

func revokeAPIKey(ctx context.Context, runner sqlRunner, keyID string, revokedAt time.Time) error {
	result, err := runner.ExecContext(
		ctx,
		`UPDATE auth_api_keys
		 SET revoked_at = $1
		 WHERE id = $2 AND revoked_at IS NULL`,
		revokedAt.UTC(),
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

	key, err := getAPIKey(ctx, runner, `WHERE id = $1`, keyID)
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
		`UPDATE auth_api_keys
		 SET last_used_at = $1
		 WHERE id = $2 AND revoked_at IS NULL`,
		usedAt.UTC(),
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

// RecordAuditEvent stores an audit event.
func (s *Store) RecordAuditEvent(ctx context.Context, event auth.AuditEvent) error {
	return recordAuditEvent(ctx, s.db, event)
}

func recordAuditEvent(ctx context.Context, runner sqlRunner, event auth.AuditEvent) error {
	metadata, err := encodeMetadata(event.Metadata)
	if err != nil {
		return err
	}
	_, err = runner.ExecContext(
		ctx,
		`INSERT INTO auth_audit_events(
			id, type, actor_id, principal_type, principal_id, api_key_id, occurred, metadata
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
		event.ID,
		event.Type,
		event.ActorID,
		event.PrincipalType,
		event.PrincipalID,
		event.APIKeyID,
		event.Occurred.UTC(),
		metadata,
	)
	return mapWriteError(err)
}

func (s *Store) getAPIKey(ctx context.Context, where string, args ...any) (auth.APIKey, error) {
	return getAPIKey(ctx, s.db, where, args...)
}

func getAPIKey(ctx context.Context, runner sqlRunner, where string, args ...any) (auth.APIKey, error) {
	query := `SELECT id, issuer, prefix, name, owner_type, owner_id, hash, scopes,
			created_at, expires_at, revoked_at, last_used_at
		FROM auth_api_keys ` + where
	row := runner.QueryRowContext(ctx, query, args...)
	return scanAPIKey(row)
}

type sqlRunner interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAPIKey(row scanner) (auth.APIKey, error) {
	var key auth.APIKey
	var scopes []byte
	var expiresAt, revokedAt, lastUsedAt sql.NullTime
	if err := row.Scan(
		&key.ID,
		&key.Issuer,
		&key.Prefix,
		&key.Name,
		&key.OwnerType,
		&key.OwnerID,
		&key.Hash,
		&scopes,
		&key.CreatedAt,
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
	key.CreatedAt = key.CreatedAt.UTC()
	key.ExpiresAt = timeFromNull(expiresAt)
	key.RevokedAt = timeFromNull(revokedAt)
	key.LastUsedAt = timeFromNull(lastUsedAt)
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
	if _, err := parseTimeString(cursor.CreatedAt); err != nil {
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

func decodeScopes(value []byte) ([]string, error) {
	var scopes []string
	if err := json.Unmarshal(value, &scopes); err != nil {
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
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503":
			return errors.Join(auth.ErrNotFound, err)
		case "23505":
			return errors.Join(auth.ErrAlreadyExists, err)
		case "23514":
			return errors.Join(auth.ErrInvalidState, err)
		}
	}

	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "foreign key"):
		return errors.Join(auth.ErrNotFound, err)
	case strings.Contains(lower, "duplicate") || strings.Contains(lower, "unique") || strings.Contains(lower, "primary key"):
		return errors.Join(auth.ErrAlreadyExists, err)
	case strings.Contains(lower, "constraint") || strings.Contains(lower, "check"):
		return errors.Join(auth.ErrInvalidState, err)
	default:
		return err
	}
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func timePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func timeFromNull(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time.UTC()
	return &t
}
