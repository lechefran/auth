package mongodb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/lechefran/auth"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const maxStoreCursorLength = 1024

// Store implements auth stores using MongoDB.
type Store struct {
	db *mongo.Database
}

// NewStore creates a MongoDB store backed by db.
func NewStore(db *mongo.Database) *Store {
	return &Store{db: db}
}

// TransactionalStore implements atomic key/audit operations using MongoDB transactions.
//
// MongoDB transactions require a replica set or sharded cluster. Use NewStore
// for standalone deployments or when best-effort audit writes are acceptable.
type TransactionalStore struct {
	*Store
}

// NewTransactionalStore creates a MongoDB store with transaction-backed
// key/audit operations.
func NewTransactionalStore(db *mongo.Database) *TransactionalStore {
	return &TransactionalStore{Store: NewStore(db)}
}

// DeleteData deletes all auth adapter data while keeping MongoDB indexes and migration records.
func (s *Store) DeleteData(ctx context.Context) error {
	return DeleteData(ctx, s.db)
}

// CreatePrincipal stores a user or group principal.
func (s *Store) CreatePrincipal(ctx context.Context, principal auth.Principal) error {
	_, err := s.principals().InsertOne(ctx, principalDocumentFromAuth(principal))
	return mapWriteError(err)
}

// GetPrincipal returns a user or group principal.
func (s *Store) GetPrincipal(ctx context.Context, principalType auth.PrincipalType, principalID string) (auth.Principal, error) {
	var doc principalDocument
	err := s.principals().FindOne(
		ctx,
		principalFilter(principalType, principalID),
		options.FindOne().SetCollation(simpleCollation()),
	).Decode(&doc)
	if err != nil {
		return auth.Principal{}, mapReadError(err)
	}
	return doc.authPrincipal(), nil
}

// CreateAPIKey stores API key metadata.
func (s *Store) CreateAPIKey(ctx context.Context, key auth.APIKey) error {
	if _, err := s.GetPrincipal(ctx, key.OwnerType, key.OwnerID); err != nil {
		return err
	}
	return createAPIKey(ctx, s.apiKeys(), key)
}

// CreateAPIKeyWithAudit stores API key metadata and its audit event atomically.
func (s *TransactionalStore) CreateAPIKeyWithAudit(ctx context.Context, key auth.APIKey, event auth.AuditEvent) error {
	return s.withTransaction(ctx, func(txCtx context.Context) error {
		if _, err := s.getPrincipal(ctx, txCtx, key.OwnerType, key.OwnerID); err != nil {
			return err
		}
		if err := createAPIKey(txCtx, s.apiKeys(), key); err != nil {
			return err
		}
		return recordAuditEvent(txCtx, s.auditEvents(), event)
	})
}

func createAPIKey(ctx context.Context, collection *mongo.Collection, key auth.APIKey) error {
	_, err := collection.InsertOne(ctx, apiKeyDocumentFromAuth(key))
	return mapWriteError(err)
}

// GetAPIKeyByID returns API key metadata by ID.
func (s *Store) GetAPIKeyByID(ctx context.Context, keyID string) (auth.APIKey, error) {
	return s.getAPIKey(ctx, bson.D{{Key: "id", Value: keyID}})
}

// GetAPIKeyByPrefix returns API key metadata by public prefix.
func (s *Store) GetAPIKeyByPrefix(ctx context.Context, prefix string) (auth.APIKey, error) {
	return s.getAPIKey(ctx, bson.D{{Key: "prefix", Value: prefix}})
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

	filter := bson.D{
		{Key: "owner_type", Value: ownerType},
		{Key: "owner_id", Value: ownerID},
	}
	if cursor != nil {
		cursorTime, err := time.Parse(time.RFC3339Nano, cursor.CreatedAt)
		if err != nil {
			return auth.Page[auth.APIKey]{}, auth.ErrInvalidRequest
		}
		filter = append(filter, bson.E{Key: "$or", Value: bson.A{
			bson.D{{Key: "created_at", Value: bson.D{{Key: "$gt", Value: cursorTime}}}},
			bson.D{
				{Key: "created_at", Value: cursorTime},
				{Key: "id", Value: bson.D{{Key: "$gt", Value: cursor.ID}}},
			},
		}})
	}

	cursorResult, err := s.apiKeys().Find(
		ctx,
		filter,
		options.Find().
			SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "id", Value: 1}}).
			SetLimit(int64(page.Limit+1)).
			SetCollation(simpleCollation()),
	)
	if err != nil {
		return auth.Page[auth.APIKey]{}, err
	}
	defer cursorResult.Close(ctx)

	keys := make([]auth.APIKey, 0, page.Limit+1)
	for cursorResult.Next(ctx) {
		var doc apiKeyDocument
		if err := cursorResult.Decode(&doc); err != nil {
			return auth.Page[auth.APIKey]{}, err
		}
		keys = append(keys, doc.authAPIKey())
	}
	if err := cursorResult.Err(); err != nil {
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
	return revokeAPIKey(ctx, s.apiKeys(), keyID, revokedAt)
}

// RevokeAPIKeyWithAudit reads and revokes an API key, then stores its audit event atomically.
func (s *TransactionalStore) RevokeAPIKeyWithAudit(ctx context.Context, keyID string, revokedAt time.Time, event auth.AuditEvent) (auth.APIKey, error) {
	var revoked auth.APIKey
	err := s.withTransaction(ctx, func(txCtx context.Context) error {
		key, err := findAndRevokeAPIKey(txCtx, s.apiKeys(), keyID, revokedAt)
		if err != nil {
			return err
		}
		event.APIKeyID = key.ID
		event.PrincipalType = key.OwnerType
		event.PrincipalID = key.OwnerID
		if err := recordAuditEvent(txCtx, s.auditEvents(), event); err != nil {
			return err
		}
		revoked = key
		return nil
	})
	return revoked, err
}

func revokeAPIKey(ctx context.Context, collection *mongo.Collection, keyID string, revokedAt time.Time) error {
	result, err := collection.UpdateOne(
		ctx,
		activeKeyFilter(keyID),
		bson.D{{Key: "$set", Value: bson.D{{Key: "revoked_at", Value: revokedAt.UTC()}}}},
		options.UpdateOne().SetCollation(simpleCollation()),
	)
	if err != nil {
		return err
	}
	if result.MatchedCount == 1 {
		return nil
	}

	key, err := getAPIKey(ctx, collection, bson.D{{Key: "id", Value: keyID}})
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

func findAndRevokeAPIKey(ctx context.Context, collection *mongo.Collection, keyID string, revokedAt time.Time) (auth.APIKey, error) {
	var doc apiKeyDocument
	err := collection.FindOneAndUpdate(
		ctx,
		activeKeyFilter(keyID),
		bson.D{{Key: "$set", Value: bson.D{{Key: "revoked_at", Value: revokedAt.UTC()}}}},
		options.FindOneAndUpdate().
			SetReturnDocument(options.After).
			SetCollation(simpleCollation()),
	).Decode(&doc)
	if err == nil {
		return doc.authAPIKey(), nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return auth.APIKey{}, err
	}

	key, err := getAPIKey(ctx, collection, bson.D{{Key: "id", Value: keyID}})
	if errors.Is(err, auth.ErrNotFound) {
		return auth.APIKey{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.APIKey{}, err
	}
	if key.RevokedAt != nil {
		return auth.APIKey{}, auth.ErrInvalidState
	}
	return auth.APIKey{}, auth.ErrConflict
}

// TouchAPIKey records successful use.
func (s *Store) TouchAPIKey(ctx context.Context, keyID string, usedAt time.Time) error {
	result, err := s.apiKeys().UpdateOne(
		ctx,
		activeKeyFilter(keyID),
		bson.D{{Key: "$set", Value: bson.D{{Key: "last_used_at", Value: usedAt.UTC()}}}},
		options.UpdateOne().SetCollation(simpleCollation()),
	)
	if err != nil {
		return err
	}
	if result.MatchedCount == 1 {
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
	return recordAuditEvent(ctx, s.auditEvents(), event)
}

func recordAuditEvent(ctx context.Context, collection *mongo.Collection, event auth.AuditEvent) error {
	_, err := collection.InsertOne(ctx, auditEventDocumentFromAuth(event))
	return mapWriteError(err)
}

func (s *Store) getPrincipal(ctx context.Context, operationCtx context.Context, principalType auth.PrincipalType, principalID string) (auth.Principal, error) {
	var doc principalDocument
	err := s.principals().FindOne(
		operationCtx,
		principalFilter(principalType, principalID),
		options.FindOne().SetCollation(simpleCollation()),
	).Decode(&doc)
	if err != nil {
		return auth.Principal{}, mapReadError(err)
	}
	return doc.authPrincipal(), nil
}

func (s *Store) getAPIKey(ctx context.Context, filter bson.D) (auth.APIKey, error) {
	return getAPIKey(ctx, s.apiKeys(), filter)
}

func getAPIKey(ctx context.Context, collection *mongo.Collection, filter bson.D) (auth.APIKey, error) {
	var doc apiKeyDocument
	err := collection.FindOne(ctx, filter, options.FindOne().SetCollation(simpleCollation())).Decode(&doc)
	if err != nil {
		return auth.APIKey{}, mapReadError(err)
	}
	return doc.authAPIKey(), nil
}

func (s *Store) withTransaction(ctx context.Context, fn func(context.Context) error) error {
	if s.db == nil {
		return errors.New("mongodb: database is required")
	}
	return s.db.Client().UseSession(ctx, func(sessionCtx context.Context) error {
		session := mongo.SessionFromContext(sessionCtx)
		_, err := session.WithTransaction(
			sessionCtx,
			func(txCtx context.Context) (any, error) {
				return nil, fn(txCtx)
			},
			options.Transaction().
				SetReadConcern(readconcern.Snapshot()).
				SetWriteConcern(writeconcern.Majority()),
		)
		return err
	})
}

func (s *Store) principals() *mongo.Collection {
	return s.db.Collection(PrincipalsCollection)
}

func (s *Store) apiKeys() *mongo.Collection {
	return s.db.Collection(APIKeysCollection)
}

func (s *Store) auditEvents() *mongo.Collection {
	return s.db.Collection(AuditEventsCollection)
}

type principalDocument struct {
	DocumentID string             `bson:"_id"`
	ID         string             `bson:"id"`
	Type       auth.PrincipalType `bson:"type"`
	Name       string             `bson:"name"`
	CreatedAt  time.Time          `bson:"created_at"`
	UpdatedAt  time.Time          `bson:"updated_at"`
	DisabledAt *time.Time         `bson:"disabled_at"`
}

func principalDocumentFromAuth(principal auth.Principal) principalDocument {
	return principalDocument{
		DocumentID: principalDocumentID(principal.Type, principal.ID),
		ID:         principal.ID,
		Type:       principal.Type,
		Name:       principal.Name,
		CreatedAt:  principal.CreatedAt.UTC(),
		UpdatedAt:  principal.UpdatedAt.UTC(),
		DisabledAt: timePtr(principal.DisabledAt),
	}
}

func (d principalDocument) authPrincipal() auth.Principal {
	return auth.Principal{
		ID:         d.ID,
		Type:       d.Type,
		Name:       d.Name,
		CreatedAt:  d.CreatedAt.UTC(),
		UpdatedAt:  d.UpdatedAt.UTC(),
		DisabledAt: timePtr(d.DisabledAt),
	}
}

type apiKeyDocument struct {
	DocumentID string             `bson:"_id"`
	ID         string             `bson:"id"`
	Issuer     string             `bson:"issuer"`
	Prefix     string             `bson:"prefix"`
	Name       string             `bson:"name"`
	OwnerType  auth.PrincipalType `bson:"owner_type"`
	OwnerID    string             `bson:"owner_id"`
	Hash       []byte             `bson:"hash"`
	Scopes     []string           `bson:"scopes"`
	CreatedAt  time.Time          `bson:"created_at"`
	ExpiresAt  *time.Time         `bson:"expires_at"`
	RevokedAt  *time.Time         `bson:"revoked_at"`
	LastUsedAt *time.Time         `bson:"last_used_at"`
}

func apiKeyDocumentFromAuth(key auth.APIKey) apiKeyDocument {
	return apiKeyDocument{
		DocumentID: key.ID,
		ID:         key.ID,
		Issuer:     key.Issuer,
		Prefix:     key.Prefix,
		Name:       key.Name,
		OwnerType:  key.OwnerType,
		OwnerID:    key.OwnerID,
		Hash:       append([]byte(nil), key.Hash...),
		Scopes:     append([]string(nil), key.Scopes...),
		CreatedAt:  key.CreatedAt.UTC(),
		ExpiresAt:  timePtr(key.ExpiresAt),
		RevokedAt:  timePtr(key.RevokedAt),
		LastUsedAt: timePtr(key.LastUsedAt),
	}
}

func (d apiKeyDocument) authAPIKey() auth.APIKey {
	return auth.APIKey{
		ID:         d.ID,
		Issuer:     d.Issuer,
		Prefix:     d.Prefix,
		Name:       d.Name,
		OwnerType:  d.OwnerType,
		OwnerID:    d.OwnerID,
		Hash:       append([]byte(nil), d.Hash...),
		Scopes:     append([]string(nil), d.Scopes...),
		CreatedAt:  d.CreatedAt.UTC(),
		ExpiresAt:  timePtr(d.ExpiresAt),
		RevokedAt:  timePtr(d.RevokedAt),
		LastUsedAt: timePtr(d.LastUsedAt),
	}
}

type auditEventDocument struct {
	DocumentID    string              `bson:"_id"`
	ID            string              `bson:"id"`
	Type          auth.AuditEventType `bson:"type"`
	ActorID       string              `bson:"actor_id"`
	PrincipalType auth.PrincipalType  `bson:"principal_type"`
	PrincipalID   string              `bson:"principal_id"`
	APIKeyID      string              `bson:"api_key_id"`
	Occurred      time.Time           `bson:"occurred"`
	Metadata      map[string]string   `bson:"metadata"`
}

func auditEventDocumentFromAuth(event auth.AuditEvent) auditEventDocument {
	metadata := event.Metadata
	if metadata == nil {
		metadata = map[string]string{}
	}
	return auditEventDocument{
		DocumentID:    event.ID,
		ID:            event.ID,
		Type:          event.Type,
		ActorID:       event.ActorID,
		PrincipalType: event.PrincipalType,
		PrincipalID:   event.PrincipalID,
		APIKeyID:      event.APIKeyID,
		Occurred:      event.Occurred.UTC(),
		Metadata:      copyMetadata(metadata),
	}
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
	if _, err := time.Parse(time.RFC3339Nano, cursor.CreatedAt); err != nil {
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

func mapReadError(err error) error {
	if errors.Is(err, mongo.ErrNoDocuments) {
		return auth.ErrNotFound
	}
	return err
}

func mapWriteError(err error) error {
	if err == nil {
		return nil
	}
	if mongo.IsDuplicateKeyError(err) {
		return errors.Join(auth.ErrAlreadyExists, err)
	}
	if isDocumentValidationError(err) {
		return errors.Join(auth.ErrInvalidState, err)
	}
	return err
}

func isDocumentValidationError(err error) bool {
	var commandErr mongo.CommandError
	if errors.As(err, &commandErr) && commandErr.Code == 121 {
		return true
	}
	var writeException mongo.WriteException
	if errors.As(err, &writeException) {
		for _, writeError := range writeException.WriteErrors {
			if writeError.Code == 121 {
				return true
			}
		}
	}
	return false
}

func principalFilter(principalType auth.PrincipalType, principalID string) bson.D {
	return bson.D{
		{Key: "type", Value: principalType},
		{Key: "id", Value: principalID},
	}
}

func activeKeyFilter(keyID string) bson.D {
	return bson.D{
		{Key: "id", Value: keyID},
		{Key: "revoked_at", Value: nil},
	}
}

func principalDocumentID(principalType auth.PrincipalType, principalID string) string {
	return string(principalType) + ":" + principalID
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func timePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	utc := t.UTC()
	return &utc
}

func simpleCollation() *options.Collation {
	return &options.Collation{Locale: "simple"}
}

func copyMetadata(metadata map[string]string) map[string]string {
	copied := make(map[string]string, len(metadata))
	for key, value := range metadata {
		copied[key] = value
	}
	return copied
}
