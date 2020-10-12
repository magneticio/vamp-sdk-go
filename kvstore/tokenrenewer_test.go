// +build integration

package kvstore

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/hashicorp/vault/api"
	. "github.com/smartystreets/goconvey/convey"
)

const vaultAddress = "http://localhost:8200"

var vaultToken = getVaultToken()

func TestIntegrationTokenRenewer(t *testing.T) {

	Convey("Given Vault client with valid token", t, func() {
		client, _ := api.NewClient(&api.Config{
			Address: vaultAddress,
		})
		client.SetToken(vaultToken)

		Convey("When creating token renewer with renewal interval set to 0", func() {
			_, err := NewTokenRenewer(client, 0, 2*time.Second)

			Convey("error should be thrown", func() {
				So(err.Error(), ShouldEqual, "Token TTL and token renewal interval must be greater than 0")
			})
		})

		Convey("When creating token renewer with token TTL set to 0", func() {
			_, err := NewTokenRenewer(client, time.Second, 0)

			Convey("error should be thrown", func() {
				So(err.Error(), ShouldEqual, "Token TTL and token renewal interval must be greater than 0")
			})
		})

		Convey("When creating token renewer with token TTL lower then renewal interval", func() {
			_, err := NewTokenRenewer(client, 2*time.Second, time.Second)

			Convey("error should be thrown", func() {
				So(err.Error(), ShouldEqual, "Token TTL must be greater than token renewal interval")
			})
		})

		Convey("and valid token renewer", func() {
			tokenRenewer, _ := NewTokenRenewer(client, time.Second, 2*time.Second)

			Convey("When renewing token", func() {
				err := tokenRenewer.renewToken()

				Convey("error should not be thrown", func() {
					So(err, ShouldBeNil)
				})
			})
		})
	})

	Convey("Given Vault client without a token", t, func() {
		client, _ := api.NewClient(&api.Config{
			Address: vaultAddress,
		})
		Convey("and valid token renewer", func() {
			tokenRenewer, _ := NewTokenRenewer(client, time.Second, 2*time.Second)

			Convey("When renewing token", func() {
				err := tokenRenewer.renewToken()

				Convey("error should be thrown", func() {
					So(err, ShouldNotBeNil)
				})
			})
		})
	})
}

// getVaultToken - gets Vault token for integration tests
func getVaultToken() string {
	resp, err := http.Get("http://localhost:8201/client-token")
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	tokenWithUnprintableChars := string(body)

	token := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, tokenWithUnprintableChars)

	return token
}
