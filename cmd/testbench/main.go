package main

import (
	"fmt"
	"log"

	"github.com/lechefran/auth"
	"github.com/lechefran/auth/password"
)

func main() {
	service, err := auth.New(auth.Config{
		Issuer: "auth-testbench",
	})
	if err != nil {
		log.Fatalf("create auth service: %v", err)
	}

	cfg := service.Config()
	fmt.Printf("issuer: %s\n", cfg.Issuer)
	fmt.Printf("access token ttl: %s\n", cfg.AccessTokenTTL)
	fmt.Printf("refresh token ttl: %s\n", cfg.RefreshTokenTTL)
	fmt.Printf("session ttl: %s\n", cfg.SessionTTL)

	hasher := password.Argon2id()
	hash, err := hasher.Hash([]byte("correct horse battery staple"))
	if err != nil {
		log.Fatalf("hash password: %v", err)
	}

	matched, needsRehash, err := hasher.Verify(hash, []byte("correct horse battery staple"))
	if err != nil {
		log.Fatalf("verify password: %v", err)
	}

	fmt.Printf("password verified: %t\n", matched)
	fmt.Printf("password needs rehash: %t\n", needsRehash)
}
