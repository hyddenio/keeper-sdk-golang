package enterprise

import (
	"testing"
)

func TestMapper(t *testing.T) {
	var node = newNodeEntity()
	var _ IEnterprisePlugin = node
	for range node.GetData() {

	}
}
