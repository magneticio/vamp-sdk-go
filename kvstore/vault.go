package kvstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/magneticio/vamp-sdk-go/logging"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var log = logging.Logger()

type VaultKeyValueStore struct {
	URL    string
	Token  string
	Params map[string]string
	Client *api.Client
	Tracer trace.Tracer
}

func NewVaultKeyValueStore(address string, token string, params map[string]string, tracer trace.Tracer) (*VaultKeyValueStore, error) {
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
		Tracer: tracer,
	}, nil
}

func (c *VaultKeyValueStore) Put(ctx context.Context, key string, value string) error {
	return c.PutData(ctx, fixPath(key), valueMap(value), -1) // -1 means new version
}

func (c *VaultKeyValueStore) Get(ctx context.Context, key string) (string, error) {
	secretValues, err := c.GetData(ctx, fixPath(key), 0) //0 means lastest version
	if err != nil {
		return "", err
	}
	value, ok := secretValues["value"].(string)
	if !ok {
		return "", nil
	}
	return value, nil
}

func (c *VaultKeyValueStore) Exists(ctx context.Context, key string) (bool, error) {
	return c.ExistsData(ctx, fixPath(key), 0) //0 means lastest version
}

func (c *VaultKeyValueStore) Delete(ctx context.Context, keyName string) error {
	err := c.DeleteData(ctx, fixPath(keyName), nil) // nil mean versions are not defined
	if err != nil {
		return fmt.Errorf("error while deleting from Vault key '%s': %v", keyName, err)
	}
	return nil
}

func (c *VaultKeyValueStore) List(ctx context.Context, key string) ([]string, error) {
	secretData, listErr := c.ListData(ctx, fixPath(key))
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

func (c *VaultKeyValueStore) getClient() (*api.Client, error) {
	if err := tryRenewToken(c.Client); err != nil {
		return nil, fmt.Errorf("cannot renew token: %v", err)
	}
	return c.Client, nil
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

func (c *VaultKeyValueStore) beforeRequest(ctx context.Context, path string, action string) context.Context {
	ctx, span := c.Tracer.Start(ctx, "vault request")
	span.SetAttributes(attribute.Key("path").String(path), attribute.Key("method").String(action))
	return ctx
}

func (c *VaultKeyValueStore) afterRequest(ctx context.Context, err error) {
	span := trace.SpanFromContext(ctx)
	defer span.End()
	if err != nil {
		span.SetAttributes(attribute.Key("error").Bool(true), attribute.Key("error_message").String(err.Error()))
	}

	return
}

func (c *VaultKeyValueStore) GetData(ctx context.Context, key string, version int) (map[string]interface{}, error) {
	var err error
	path := sanitizePath(key)
	c.beforeRequest(ctx, path, http.MethodGet)
	defer c.afterRequest(ctx, err)

	client, err := c.getClient()
	if err != nil {
		return nil, fmt.Errorf("cannot get client: %v", err)
	}
	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return nil, fmt.Errorf("error checking version for path '%s': %v", path, err)
	}

	var versionParam map[string]string

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
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

func (c *VaultKeyValueStore) ExistsData(ctx context.Context, key string, version int) (bool, error) {
	var err error
	path := sanitizePath(key)
	c.beforeRequest(ctx, path, http.MethodGet)
	defer c.afterRequest(ctx, err)

	client, err := c.getClient()
	if err != nil {
		return false, fmt.Errorf("cannot get client: %v", err)
	}
	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return false, fmt.Errorf("error checking version '%s': %s", path, err)
	}

	var versionParam map[string]string

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
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

func (c *VaultKeyValueStore) PutData(ctx context.Context, key string, data map[string]interface{}, cas int) error {
	var err error
	path := sanitizePath(key)
	c.beforeRequest(ctx, path, http.MethodPut)
	defer c.afterRequest(ctx, err)

	client, err := c.getClient()
	if err != nil {
		return fmt.Errorf("cannot get client: %v", err)
	}

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return err
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

	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing data to '%s': %v", path, err)
	}
	if secret == nil {
		return nil
	}
	return nil
}

func (c *VaultKeyValueStore) DeleteData(ctx context.Context, key string, versions []string) error {
	var err error
	path := sanitizePath(key)
	c.beforeRequest(ctx, path, http.MethodDelete)
	defer c.afterRequest(ctx, err)

	client, err := c.getClient()
	if err != nil {
		return fmt.Errorf("cannot get client: %v", err)
	}
	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return err
	}

	if v2 {
		_, err = c.deleteV2(ctx, path, mountPath, versions, true)
	} else {
		_, err = client.Logical().Delete(path)
	}

	if err != nil {
		return fmt.Errorf("error deleting '%s': %v", path, err)
	}
	return nil
}

func (c *VaultKeyValueStore) ListData(ctx context.Context, key string) (map[string]interface{}, error) {
	var err error
	path := ensureTrailingSlash(sanitizePath(key))
	c.beforeRequest(ctx, path, http.MethodGet)
	defer c.afterRequest(ctx, err)

	client, err := c.getClient()
	if err != nil {
		return nil, fmt.Errorf("cannot get client: %v", err)
	}
	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return nil, err
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "metadata")
	}

	secret, err := client.Logical().List(path)
	if err != nil {
		return nil, fmt.Errorf("error listing '%s': %v", path, err)
	}
	if secret == nil || secret.Data == nil {
		return map[string]interface{}{}, nil
	}

	if _, ok := extractListData(secret); !ok {
		return nil, fmt.Errorf("no entries found at '%s'", path)
	}

	return secret.Data, nil
}

func tryRenewToken(client *api.Client) error {
	auth := client.Auth()
	if auth == nil {
		return fmt.Errorf("auth not found")
	}

	token := auth.Token()
	if token == nil {
		return fmt.Errorf("token not found")
	}

	tokenSecret, err := token.LookupSelf()
	if err != nil {
		return fmt.Errorf("cannot lookup token: %v", err)
	}

	isRenewable, err := tokenSecret.TokenIsRenewable()
	if err != nil {
		return fmt.Errorf("cannot check if token is renewable: %v", err)
	}

	if !isRenewable {
		return nil
	}

	increment, err := getTokenIncrement(tokenSecret)
	if err != nil {
		return fmt.Errorf("cannot get token increment: %v", err)
	}

	tokenCurrentTTL, err := tokenSecret.TokenTTL()
	if err != nil {
		return fmt.Errorf("cannot get token TTL: %v", err)
	}

	tokenCurrentTTLSeconds := int(tokenCurrentTTL / time.Second)

	if tokenCurrentTTLSeconds <= increment/2 {
		log.Debugf("Vault: refreshing token using increment: %d", increment)
		if _, err := token.RenewSelf(increment); err != nil {
			return fmt.Errorf("cannot refresh token: %v", err)
		}
		log.Debugf("Vault: refreshing token succeeded")
	}

	return nil
}

func getTokenIncrement(token *api.Secret) (int, error) {
	_, ok := token.Data["period"]
	if !ok {
		return getTokenIncrementFromCreationTTL(token)
	}
	return getTokenIncrementFromPeriod(token)
}

func getTokenIncrementFromPeriod(token *api.Secret) (int, error) {
	return getTokenIncrementFromNumberDataField(token, "period")
}

func getTokenIncrementFromCreationTTL(token *api.Secret) (int, error) {
	return getTokenIncrementFromNumberDataField(token, "creation_ttl")
}

func getTokenIncrementFromNumberDataField(token *api.Secret, field string) (int, error) {
	fieldValue, ok := token.Data[field]
	if !ok {
		return 0, fmt.Errorf("%s not found in token data", field)
	}
	fieldValueJSONNumber, ok := fieldValue.(json.Number)
	if !ok {
		return 0, fmt.Errorf("invalid type of %s in token data", field)
	}
	fieldValueInt, err := strconv.Atoi(string(fieldValueJSONNumber))
	if err != nil {
		return 0, fmt.Errorf("cannot parse %s value: %v", field, err)
	}
	return fieldValueInt, nil
}
