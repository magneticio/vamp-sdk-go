package kvstore

import (
	"context"
	"errors"

	configuration "github.com/magneticio/vamp-sdk-go/configuration"
	"go.opentelemetry.io/otel/trace"
)

type KeyValueStore interface {
	Get(context.Context, string) (string, error)
	Exists(context.Context, string) (bool, error)
	Put(context.Context, string, string) error
	Delete(context.Context, string) error
	List(context.Context, string) ([]string, error)
}

func NewKeyValueStore(config configuration.KeyValueStoreConfiguration, tracer trace.Tracer) (KeyValueStore, error) {
	if config.Type == "vault" {
		params := map[string]string{
			"cert":   config.Vault.ClientTlsCert,
			"key":    config.Vault.ClientTlsKey,
			"caCert": config.Vault.ServerTlsCert,
		}
		vaultKVclient, vaultKVclientError := NewVaultKeyValueStore(config.Vault.Url, config.Vault.Token, params, tracer)
		if vaultKVclientError != nil {
			return nil, vaultKVclientError
		}
		return vaultKVclient, nil
	}
	return nil, errors.New("Unsupported Key Value Store Client: " + config.Type)
}
