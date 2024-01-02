package api

import (
	"gotest.tools/assert"
	"testing"
)

func TestSet(t *testing.T) {
	var a = []string{"sdssdsdsd", "sdfddfdfdfd"}
	var b = a[:99]
	assert.Assert(t, len(b) == 1)
}
