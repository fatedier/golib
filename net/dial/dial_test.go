package dial

import (
	"net"
	"testing"

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
