package dial

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

	c, err := Dial("2.3.3.3", WithTimeout(100*time.Millisecond))
	require.Error(err)
	require.Nil(c)
}
