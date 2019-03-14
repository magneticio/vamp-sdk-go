package kvstore

import (
	"errors"

	configuration "github.com/magneticio/vamp-sdk-go/configuration"
)

type KeyValueStore interface {
	Get(string) (string, error)
	Exists(string) (bool, error)
	Put(string, string) error
	Delete(string) error
	List(string) ([]string, error)
}

func NewKeyValueStore(config configuration.KeyValueStoreConfiguration) (KeyValueStore, error) {
	if config.Type == "vault" {
		params := map[string]string{
			"cert":   config.Vault.ClientTlsCert,
			"key":    config.Vault.ClientTlsKey,
			"caCert": config.Vault.ServerTlsCert,
		}
		vaultKVclient, vaultKVclientError := NewVaultKeyValueStore(config.Vault.Url, config.Vault.Token, params)
		if vaultKVclientError != nil {
			return nil, vaultKVclientError
		}
		return vaultKVclient, nil
	}
	return nil, errors.New("Unsupported Key Value Store Client: " + config.Type)
}
