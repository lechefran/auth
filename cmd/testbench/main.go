package main

import (
	"fmt"
	"log"

	"github.com/lechefran/auth"
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
}
