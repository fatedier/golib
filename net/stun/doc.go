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

// Package stun implements minimal STUN message decoding and Binding
// transactions.
//
// Message is the binary codec layer. It owns its bytes, strictly validates
// framing, and does not expose arbitrary STUN attribute construction.
// BindingTransaction adds Binding request construction, transaction matching,
// and expected-source validation. Client is the synchronous network I/O layer
// over the same transaction core:
//
//	client, err := stun.NewClient(conn)
//	transaction, err := stun.NewBindingTransaction(server)
//	response, err := client.Do(transaction)
//
// Callers that already own a UDP read loop can use the transaction directly:
//
//	transaction, err := stun.NewBindingTransaction(server)
//	request, err := transaction.MarshalBinary()
//	_, err = conn.WriteToUDP(request, server)
//	// Read packet and source using the caller's existing demultiplexer.
//	response, matched, err := transaction.Process(packet, source)
//
// Client borrows its UDP connection. The caller remains responsible for its
// deadlines, lifetime, and serializing reads while Client.Do is running. The
// package does not create or close sockets, retry requests, start background
// goroutines, discover NAT behavior, or implement authentication, TURN, or ICE.
// Binding responses support both IPv4 and IPv6 address attributes.
package stun
