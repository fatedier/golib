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

type TestStruct struct{}

type (
	Ping struct{}
	Pong struct{}
)

type Login struct {
	User string `json:"user"`
}

var (
	TypePing  byte = '1'
	TypePong  byte = '2'
	TypeLogin byte = '3'

	msgCtl = NewMsgCtl()
)

func init() {
	msgCtl.RegisterMsg(TypePing, Ping{})
	msgCtl.RegisterMsg(TypePong, Pong{})
	msgCtl.RegisterMsg(TypeLogin, Login{})
}

func TestPack(t *testing.T) {
	assert := assert.New(t)

	var msg Message
	// error type
	msg = &TestStruct{}
	_, err := msgCtl.Pack(msg)
	assert.Equal(err, ErrMsgType)

	// correct
	msg = &Ping{}
	buffer, err := msgCtl.Pack(msg)
	assert.NoError(err)
	b := bytes.NewBuffer(nil)
	b.WriteByte(TypePing)
	binary.Write(b, binary.BigEndian, int64(2))
	b.WriteString("{}")
	assert.True(bytes.Equal(b.Bytes(), buffer))
}

func TestUnPack(t *testing.T) {
	assert := assert.New(t)

	// error message type
	_, err := msgCtl.UnPack('-', []byte("{}"))
	assert.Error(err)

	// correct
	msg, err := msgCtl.UnPack(TypePong, []byte("{}"))
	assert.NoError(err)
	assert.Equal(reflect.TypeOf(msg).Elem(), reflect.TypeOf(Pong{}))
}

func TestUnPackInto(t *testing.T) {
	assert := assert.New(t)

	var err error

	// correct type
	pongMsg := &Pong{}
	err = msgCtl.UnPackInto([]byte("{}"), pongMsg)
	assert.NoError(err)

	// wrong type
	loginMsg := &Login{}
	err = msgCtl.UnPackInto([]byte(`{"user": 123}`), loginMsg)
	assert.Error(err)
}
