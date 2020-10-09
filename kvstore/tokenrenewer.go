package kvstore

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

// TokenRenewer - struct responsible for Vault token renewal process
type TokenRenewer struct {
	client             *api.Client
	tokenRenewInterval time.Duration
	tokenTTL           time.Duration
}

// NewTokenRenewer - returns a new token renewer
func NewTokenRenewer(client *api.Client, tokenRenewInterval, tokenTTL time.Duration) (*TokenRenewer, error) {
	if tokenTTL == 0 || tokenRenewInterval == 0 {
		return nil, fmt.Errorf("Token TTL and token renew interval must be greater than 0")
	}

	if tokenTTL <= tokenRenewInterval {
		return nil, fmt.Errorf("Token TTL must be greater than token renew interval")
	}

	return &TokenRenewer{
		client:             client,
		tokenRenewInterval: tokenRenewInterval,
		tokenTTL:           tokenTTL,
	}, nil
}

// Run - runs the renewal process
func (tr *TokenRenewer) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(tr.tokenRenewInterval):
			if err := tr.renewToken(); err != nil {
				log.Errorf("Cannot renew Vault token: %v", err)
			}
		}
	}
}

func (tr *TokenRenewer) renewToken() error {
	increment := int(tr.tokenTTL / time.Second)
	log.Debugf("Renewing Vault token using increment: %d", increment)
	if _, err := tr.client.Auth().Token().RenewSelf(increment); err != nil {
		return err
	}
	log.Debugf("Renewing Vault token succeeded")
	return nil
}
