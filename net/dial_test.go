package net

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDial(t *testing.T) {
	require := require.New(t)

	l, err := net.Listen("tcp", "127.0.0.1:")
	require.NoError(err)

	c, err := Dial(l.Addr().String())
	require.NoError(err)
	require.NotNil(c)
	c.Close()
}

func TestDialTimeout(t *testing.T) {
	require := require.New(t)

	timeout := 200 * time.Millisecond
	start := time.Now()
	c, err := Dial("2.3.3.3:80", WithTimeout(timeout))
	end := time.Now()
	require.Error(err)
	require.Nil(c)
	require.Truef(end.After(start.Add(timeout)), "start: %v, end: %v", start, end)
	require.True(end.Before(start.Add(2*timeout)), "start: %v, end: %v", start, end)
}
