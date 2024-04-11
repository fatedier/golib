// Copyright 2018 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package json

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

type StartWorkConn struct {
	ProxyName string `json:"proxy_name"`
}

var TypeStartWorkConn byte = '4'

func init() {
	msgCtl.RegisterMsg(TypeStartWorkConn, StartWorkConn{})
}

func TestProcess(t *testing.T) {
	assert := assert.New(t)

	var (
		msg    Message
		resMsg Message
		err    error
	)
	// empty struct
	msg = &Ping{}
	buffer := bytes.NewBuffer(nil)
	err = msgCtl.WriteMsg(buffer, msg)
	assert.NoError(err)

	resMsg, err = msgCtl.ReadMsg(buffer)
	assert.NoError(err)
	assert.Equal(reflect.TypeOf(resMsg).Elem(), msgCtl.typeMap[TypePing])

	// normal message
	msg = &StartWorkConn{
		ProxyName: "test",
	}
	buffer = bytes.NewBuffer(nil)
	err = msgCtl.WriteMsg(buffer, msg)
	assert.NoError(err)

	resMsg, err = msgCtl.ReadMsg(buffer)
	assert.NoError(err)
	assert.Equal(reflect.TypeOf(resMsg).Elem(), msgCtl.typeMap[TypeStartWorkConn])

	startWorkConnMsg, ok := resMsg.(*StartWorkConn)
	assert.True(ok)
	assert.Equal("test", startWorkConnMsg.ProxyName)

	// ReadMsgInto correct
	msg = &Pong{}
	buffer = bytes.NewBuffer(nil)
	err = msgCtl.WriteMsg(buffer, msg)
	assert.NoError(err)

	err = msgCtl.ReadMsgInto(buffer, msg)
	assert.NoError(err)

	// ReadMsgInto error type
	content := []byte(`{"user": 123}`)
	buffer = bytes.NewBuffer(nil)
	buffer.WriteByte(TypeStartWorkConn)
	binary.Write(buffer, binary.BigEndian, int64(len(content)))
	buffer.Write(content)

	resMsg = &Login{}
	err = msgCtl.ReadMsgInto(buffer, resMsg)
	assert.Error(err)

	// message format error
	buffer = bytes.NewBuffer([]byte("1234"))

	resMsg = &Ping{}
	err = msgCtl.ReadMsgInto(buffer, resMsg)
	assert.Error(err)

	// MaxLength, real message length is 2
	msgCtl.SetMaxMsgLength(1)
	msg = &Ping{}
	buffer = bytes.NewBuffer(nil)
	err = msgCtl.WriteMsg(buffer, msg)
	assert.NoError(err)

	_, err = msgCtl.ReadMsg(buffer)
	assert.Error(err)

	msgCtl.SetMaxMsgLength(defaultMaxMsgLength)
}
