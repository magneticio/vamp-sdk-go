package kvstore

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/magneticio/forklift/logging"
)

type VaultKeyValueStore struct {
	URL    string
	Token  string
	Params map[string]string
	Client *api.Client
}

func NewVaultKeyValueStore(address string, token string, params map[string]string) (*VaultKeyValueStore, error) {

	logging.Info("Initialising Vault Client with address %v\n", address)

	config, configErr := getConfig(address, params["cert"], params["key"], params["caCert"])
	if configErr != nil {
		logging.Error("Error getting config %v\n", configErr.Error())
		return nil, configErr
	}

	client, err := api.NewClient(config)
	if err != nil {
		logging.Error("Error initialising client %v\n", err.Error())
		return nil, err
	}

	client.SetToken(token)

	return &VaultKeyValueStore{
		URL:    address,
		Token:  token,
		Params: params,
		Client: client,
	}, nil
}

func (c *VaultKeyValueStore) Put(key string, value string) error {
	return c.PutData(fixPath(key), valueMap(value), -1) // -1 means new version
}

func (c *VaultKeyValueStore) Get(key string) (string, error) {
	secretValues, err := c.GetData(fixPath(key), 0) //0 means lastest version
	if err != nil {
		return "", err
	}
	value, ok := secretValues["value"].(string)
	if !ok {
		return "", nil
	}
	return value, nil
}

func (c *VaultKeyValueStore) Exists(key string) (bool, error) {
	return c.ExistsData(fixPath(key), 0) //0 means lastest version
}

func (c *VaultKeyValueStore) Delete(keyName string) error {
	logging.Info("Deleting from Vault key %v\n", keyName)
	err := c.DeleteData(fixPath(keyName), nil) // nil mean versions are not defined
	if err != nil {
		logging.Error("Error while deleting from Vault key %v - %v\n", keyName, err.Error())
		return err
	}
	return nil
}

func (c *VaultKeyValueStore) List(key string) ([]string, error) {
	logging.Info("Getting list from Vault with key %v\n", key)
	secretData, listErr := c.ListData(fixPath(key))
	if listErr != nil {
		logging.Error("Error while getting list from Vault with key %v - %v\n", key, listErr.Error())
		return nil, listErr
	}
	if secretData == nil {
		return nil, errors.New("List is not available for path: " + key)
	}
	if val, ok := secretData["keys"]; ok {
		if keysTemp, castOk := val.([]interface{}); castOk {
			keys := make([]string, len(keysTemp))
			for index, k := range keysTemp {
				if str, strCastOk := k.(string); strCastOk {
					keys[index] = fixPathSuffix(str)
				}
			}
			return keys, nil
		}
	}
	return nil, errors.New("List is not available for path: " + key)
}

func getConfig(address, cert, key, caCert string) (*api.Config, error) {
	conf := api.DefaultConfig()
	conf.Address = address

	tlsConfig := &tls.Config{}
	if cert != "" && key != "" {
		clientCert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
		tlsConfig.BuildNameToCertificate()
	}

	if caCert != "" {
		ca, err := ioutil.ReadFile(caCert)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(ca)
		tlsConfig.RootCAs = caCertPool
	}

	conf.HttpClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return conf, nil
}

func (c *VaultKeyValueStore) getClient() *api.Client {
	// TODO: This will check for token renewal
	return c.Client
}

func fixPath(path string) string {
	if strings.HasPrefix(path, "/") {
		return strings.TrimPrefix(path, "/")
	}
	return path
}

func fixPathSuffix(path string) string {
	return strings.TrimSuffix(path, "/")
}

func valueMap(value string) map[string]interface{} {
	return map[string]interface{}{
		"value": value,
	}
}

// Vault API

func (c *VaultKeyValueStore) GetData(key string, version int) (map[string]interface{}, error) {
	client := c.getClient()
	path := sanitizePath(key)
	mountPath, v2, pathError := isKVv2(path, client)
	if pathError != nil {
		logging.Error("Error checking version %s: %s", path, pathError)
		return nil, pathError
	}

	var versionParam map[string]string

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
		logging.Info("Prefix added to the kv path %v", path)
		if version > 0 {
			versionParam = map[string]string{
				"version": fmt.Sprintf("%d", version),
			}
		}
	}

	secret, err := kvReadRequest(client, path, versionParam)
	if err != nil {
		logging.Error("Error reading %s: %s", path, err)
		if secret != nil {
			return secret.Data, nil
		}
		return nil, fmt.Errorf("No value found at %s", path)
	}
	if secret == nil {
		logging.Error("No value found at %s", path)
		return nil, fmt.Errorf("No value found at %s", path)
	}

	data := secret.Data
	if v2 && data != nil {
		data = nil
		dataRaw := secret.Data["data"]
		if dataRaw != nil {
			data = dataRaw.(map[string]interface{})
		}
	}

	if data != nil {
		return data, nil
	}

	return nil, fmt.Errorf("No value found at %s", path)
}

func (c *VaultKeyValueStore) ExistsData(key string, version int) (bool, error) {
	client := c.getClient()
	path := sanitizePath(key)
	mountPath, v2, pathError := isKVv2(path, client)
	if pathError != nil {
		logging.Error("Error checking version %s: %s", path, pathError)
		return false, pathError
	}

	var versionParam map[string]string

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
		logging.Info("Prefix added to the kv path %v", path)
		if version > 0 {
			versionParam = map[string]string{
				"version": fmt.Sprintf("%d", version),
			}
		}
	}

	secret, err := kvReadRequest(client, path, versionParam)
	if err != nil {
		logging.Error("Error reading %s: %s", path, err)
		if secret != nil {
			return true, nil
		}
		return false, err
	}
	if secret == nil {
		return false, nil
	}

	data := secret.Data
	if v2 && data != nil {
		data = nil
		dataRaw := secret.Data["data"]
		if dataRaw != nil {
			data = dataRaw.(map[string]interface{})
		}
	}

	if data != nil {
		return true, nil
	}

	return false, nil
}

func (c *VaultKeyValueStore) PutData(key string, data map[string]interface{}, cas int) error {
	client := c.getClient()
	path := sanitizePath(key)

	mountPath, v2, pathError := isKVv2(path, client)
	if pathError != nil {
		logging.Error(pathError.Error())
		return pathError
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
		data = map[string]interface{}{
			"data":    data,
			"options": map[string]interface{}{},
		}

		if cas > -1 {
			data["options"].(map[string]interface{})["cas"] = cas
		}
	}

	secret, writeError := client.Logical().Write(path, data)
	if writeError != nil {
		logging.Error("Error writing data to %s: %s", path, writeError)
		if secret != nil {
			logging.Info("Secret: %v\n", secret)
		}
		return writeError
	}
	if secret == nil {
		logging.Info("Success! Data written to: %s", path)
		return nil
	}
	return nil
}

func (c *VaultKeyValueStore) DeleteData(key string, versions []string) error {
	client := c.getClient()
	path := sanitizePath(key)
	mountPath, v2, pathError := isKVv2(path, client)
	if pathError != nil {
		logging.Error(pathError.Error())
		return pathError
	}

	var secret *api.Secret
	var deleteError error
	if v2 {
		secret, deleteError = c.deleteV2(path, mountPath, versions, true)
	} else {
		secret, deleteError = client.Logical().Delete(path)
	}

	if deleteError != nil {
		logging.Error("Error deleting %s: %s", path, deleteError)
		if secret != nil {
			logging.Info("Secret %v\n", secret)
		}
		return deleteError
	}

	logging.Info("Success! Data deleted (if it existed) at: %s", path)
	return nil
}

func (c *VaultKeyValueStore) ListData(key string) (map[string]interface{}, error) {
	client := c.getClient()
	path := ensureTrailingSlash(sanitizePath(key))
	mountPath, v2, pathError := isKVv2(path, client)
	if pathError != nil {
		logging.Error(pathError.Error())
		return nil, pathError
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "metadata")
	}

	secret, listError := client.Logical().List(path)
	if listError != nil {
		logging.Error("Error listing %s: %s", path, listError.Error())
		return nil, listError
	}
	if secret == nil || secret.Data == nil {
		logging.Error(fmt.Sprintf("No value found at %s", path))
		return nil, fmt.Errorf("No value found at %s", path)
	}

	// If the secret is wrapped, return the wrapped response.
	if secret.WrapInfo != nil && secret.WrapInfo.TTL != 0 {
		logging.Info("Wrapped Secret %v\n", secret)
		// TODO: handle wrapped secret
	}

	if _, ok := extractListData(secret); !ok {
		logging.Error(fmt.Sprintf("No entries found at %s", path))
		return nil, fmt.Errorf("No entries found at %s", path)
	}

	return secret.Data, nil
}
