// Copyright 2026 fatedier, fatedier@gmail.com
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

package stun

import (
	"errors"
	"fmt"
)

var (
	// ErrMalformedResponse indicates invalid STUN framing or an invalid
	// supported attribute. BindingTransaction only returns it after a datagram
	// has been associated with the transaction.
	ErrMalformedResponse = errors.New("malformed STUN response")
	// ErrUnsupportedAddressFamily indicates that an address attribute uses an
	// address family other than IPv4 or IPv6.
	ErrUnsupportedAddressFamily = errors.New("unsupported STUN address family")
)

// ResponseError describes an error returned by a STUN Binding server.
type ResponseError struct {
	// Code is the numeric STUN error code.
	Code int
	// Reason is the server-provided reason phrase.
	Reason string
}

// Error implements error.
func (e *ResponseError) Error() string {
	if e == nil {
		return "STUN binding error response"
	}
	if e.Reason == "" {
		return fmt.Sprintf("STUN binding error %d", e.Code)
	}
	return fmt.Sprintf("STUN binding error %d: %s", e.Code, e.Reason)
}

func malformedResponsef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformedResponse, fmt.Sprintf(format, args...))
}
