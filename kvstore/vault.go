package kvstore

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/magneticio/vamp-sdk-go/logging"
)

var log = logging.Logger()

type VaultKeyValueStore struct {
	URL    string
	Token  string
	Params map[string]string
	Client *api.Client
}

func NewVaultKeyValueStore(address string, token string, params map[string]string) (*VaultKeyValueStore, error) {

	log.Infof("Initialising Vault Client with address %s", address)

	config, configErr := getConfig(address, params["cert"], params["key"], params["caCert"])
	if configErr != nil {
		return nil, fmt.Errorf("error getting config: %v", configErr)
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("error initialising client: %v", err)
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
	err := c.DeleteData(fixPath(keyName), nil) // nil mean versions are not defined
	if err != nil {
		return fmt.Errorf("error while deleting from Vault key '%s': %v", keyName, err)
	}
	return nil
}

func (c *VaultKeyValueStore) List(key string) ([]string, error) {
	secretData, listErr := c.ListData(fixPath(key))
	if listErr != nil {
		return nil, fmt.Errorf("error while getting list from Vault with key '%s': %v", key, listErr)
	}
	if secretData == nil {
		return nil, fmt.Errorf("list is not available for key '%s'", key)
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
	return nil, fmt.Errorf("list is not available for key '%s'", key)
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
		return nil, fmt.Errorf("error checking version for path '%s': %v", path, pathError)
	}

	var versionParam map[string]string

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
		log.Debugf("prefix added to the kv path '%s'", path)
		if version > 0 {
			versionParam = map[string]string{
				"version": fmt.Sprintf("%d", version),
			}
		}
	}

	secret, err := kvReadRequest(client, path, versionParam)
	if err != nil {
		if secret != nil {
			return secret.Data, nil
		}
		return nil, fmt.Errorf("no value found at '%s'", path)
	}
	if secret == nil {
		return nil, fmt.Errorf("no value found at '%s'", path)
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

	return nil, fmt.Errorf("no value found at '%s'", path)
}

func (c *VaultKeyValueStore) ExistsData(key string, version int) (bool, error) {
	client := c.getClient()
	path := sanitizePath(key)
	mountPath, v2, pathError := isKVv2(path, client)
	if pathError != nil {
		return false, fmt.Errorf("error checking version '%s': %s", path, pathError)
	}

	var versionParam map[string]string

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
		log.Debugf("prefix added to the kv path '%s'", path)
		if version > 0 {
			versionParam = map[string]string{
				"version": fmt.Sprintf("%d", version),
			}
		}
	}

	secret, err := kvReadRequest(client, path, versionParam)
	if err != nil {
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
		return fmt.Errorf("error writing data to '%s': %v", path, writeError)
	}
	if secret == nil {
		return nil
	}
	return nil
}

func (c *VaultKeyValueStore) DeleteData(key string, versions []string) error {
	client := c.getClient()
	path := sanitizePath(key)
	mountPath, v2, pathError := isKVv2(path, client)
	if pathError != nil {
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
		return fmt.Errorf("error deleting '%s': %v", path, deleteError)
	}
	return nil
}

func (c *VaultKeyValueStore) ListData(key string) (map[string]interface{}, error) {
	client := c.getClient()
	path := ensureTrailingSlash(sanitizePath(key))
	mountPath, v2, pathError := isKVv2(path, client)
	if pathError != nil {
		return nil, pathError
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "metadata")
	}

	secret, listError := client.Logical().List(path)
	if listError != nil {
		return nil, fmt.Errorf("error listing '%s': %v", path, listError)
	}
	if secret == nil || secret.Data == nil {
		log.Debugf(fmt.Sprintf("no value found at '%s'", path))
		return map[string]interface{}{}, nil
	}

	if _, ok := extractListData(secret); !ok {
		return nil, fmt.Errorf("no entries found at '%s'", path)
	}

	return secret.Data, nil
}
