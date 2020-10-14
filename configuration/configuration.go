package configuration

type VaultKeyValueStoreConfiguration struct {
	Url               string `yaml:"url,omitempty" json:"url,omitempty"`
	Token             string `yaml:"token,omitempty" json:"token,omitempty"`
	KvMode            string `yaml:"kv-mode,omitempty" json:"kv-mode,omitempty"`
	FallbackKvVersion int    `yaml:"fallback-kv-version,omitempty" json:"fallback-kv-version,omitempty"`
	ServerTlsCert     string `yaml:"server-tls-cert,omitempty" json:"server-tls-cert,omitempty"`
	ClientTlsKey      string `yaml:"client-tls-key,omitempty" json:"client-tls-key,omitempty"`
	ClientTlsCert     string `yaml:"client-tls-cert,omitempty" json:"client-tls-cert,omitempty"`
}

type KeyValueStoreConfiguration struct {
	Type     string                          `yaml:"type,omitempty" json:"type,omitempty"`
	BasePath string                          `yaml:"base-path,omitempty" json:"base-path,omitempty"`
	Vault    VaultKeyValueStoreConfiguration `yaml:"vault,omitempty" json:"vault,omitempty"`
}
