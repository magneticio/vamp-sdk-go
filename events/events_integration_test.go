// +build integration

package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvents_E2E_ConnectToNATS(t *testing.T) {
	natTopic := "test-topic"
	natsClusterId := "test-cluster"
	natsClientId := "vamp123"
	natsUrl := "127.0.0.1:4222"

	events := &Events{}
	err := events.Init(natsClusterId, natsClientId, natsUrl, "", "", "", "", "", "", false)
	assert.Nil(t, err)

	err = events.Subscribe(natTopic)
	assert.Nil(t, err)
}

//func TestEvents_E2E_ConnectToNATSWithToken(t *testing.T) {
//	natTopic := "test-topic"
//	natsClusterId := "test-cluster"
//	natsClientId := "vamp123"
//	natsUrl := "127.0.0.1:4222"
//	natsToken := "1234567890"
//
//	events := &Events{}
//	err :=  events.Init(natsClusterId, natsClientId, natsUrl, "", "", "", "", "", natsToken)
//	assert.Nil(t,err)
//
//	err = events.Subscribe(natTopic)
//	assert.Nil(t,err)
//}
//
//func TestEvents_E2E_ConnectToNATSWithUserPwd(t *testing.T) {
//	natTopic := "test-topic"
//	natsClusterId := "test-cluster"
//	natsClientId := "vamp123"
//	natsUrl := "127.0.0.1:4222"
//	natsUser := "test-user"
//	natsPassword := "test-pwd"
//
//	events := &Events{}
//	err :=  events.Init(natsClusterId, natsClientId, natsUrl, "", "", "", natsUser, natsPassword, "")
//	assert.Nil(t,err)
//
//	err = events.Subscribe(natTopic)
//	assert.Nil(t,err)
//}
