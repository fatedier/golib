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

package pool

import (
	"sync"
)

var (
	bufPool16k sync.Pool
	bufPool5k  sync.Pool
	bufPool2k  sync.Pool
	bufPool1k  sync.Pool
	bufPool    sync.Pool
)

func GetBuf(size int) []byte {
	var x interface{}
	switch {
	case size >= 16*1024:
		x = bufPool16k.Get()
	case size >= 5*1024:
		x = bufPool5k.Get()
	case size >= 2*1024:
		x = bufPool2k.Get()
	case size >= 1*1024:
		x = bufPool1k.Get()
	default:
		x = bufPool.Get()
	}

	if x == nil {
		return make([]byte, size)
	}
	buf := x.([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

func PutBuf(buf []byte) {
	size := cap(buf)
	switch {
	case size >= 16*1024:
		bufPool16k.Put(buf)
	case size >= 5*1024:
		bufPool5k.Put(buf)
	case size >= 2*1024:
		bufPool2k.Put(buf)
	case size >= 1*1024:
		bufPool1k.Put(buf)
	default:
		bufPool.Put(buf)
	}
}

type Buffer struct {
	pool sync.Pool
}

func NewBuffer(size int) *Buffer {
	return &Buffer{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
	}
}

func (p *Buffer) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *Buffer) Put(buf []byte) {
	p.pool.Put(buf)
}
