package limit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLimit(t *testing.T) {
	assert := assert.New(t)

	testLimiter := NewLimiter(2)
	assert.Equal(2, int(testLimiter.LimitNum()))
	assert.Equal(0, int(testLimiter.RunningNum()))
	assert.Equal(0, int(testLimiter.WaitingNum()))

	var err error
	// acquire
	err = testLimiter.Acquire(100 * time.Millisecond)
	assert.Nil(err)

	err = testLimiter.Acquire(100 * time.Millisecond)
	assert.Nil(err)

	// timeout
	err = testLimiter.Acquire(100 * time.Millisecond)
	assert.Equal(ErrTimeout, err)
	assert.Equal(2, int(testLimiter.RunningNum()))

	// change limit
	testLimiter.SetLimit(3)
	err = testLimiter.Acquire(100 * time.Millisecond)
	assert.Nil(err)

	err = testLimiter.Acquire(100 * time.Millisecond)
	assert.Equal(ErrTimeout, err)
	assert.Equal(3, int(testLimiter.RunningNum()))

	// release
	testLimiter.Release()

	err = testLimiter.Acquire(100 * time.Millisecond)
	assert.Nil(err)

	// close
	testLimiter.Close()

	err = testLimiter.Acquire(100 * time.Millisecond)
	assert.Equal(ErrClosed, err)

	// can close many times
	testLimiter.Close()
}
