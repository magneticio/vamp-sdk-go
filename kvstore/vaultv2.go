package kvstore

import "github.com/hashicorp/vault/api"

func (c *VaultKeyValueStore) deleteV2(path, mountPath string, versions []string, allVersions bool) (*api.Secret, error) {
	client := c.getClient()
	var err error
	var secret *api.Secret
	switch {
	case len(versions) > 0:
		path = addPrefixToVKVPath(path, mountPath, "delete")
		if err != nil {
			return nil, err
		}

		data := map[string]interface{}{
			"versions": kvParseVersionsFlags(versions),
		}

		secret, err = client.Logical().Write(path, data)
	default:
		prefix := "data"
		if allVersions {
			// this deletes all versions of data
			prefix = "metadata"
		}
		path = addPrefixToVKVPath(path, mountPath, prefix)
		if err != nil {
			return nil, err
		}

		secret, err = client.Logical().Delete(path)
	}

	return secret, err
}
