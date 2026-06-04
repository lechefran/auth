// Package redis provides Redis migration helpers for auth stores.
package redis

import (
	"context"
	"errors"

	goredis "github.com/redis/go-redis/v9"
)

// Open opens a Redis client and verifies connectivity.
func Open(ctx context.Context, options *goredis.Options) (*goredis.Client, error) {
	if options == nil {
		return nil, errors.New("redis: options are required")
	}
	client := goredis.NewClient(options)
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}
