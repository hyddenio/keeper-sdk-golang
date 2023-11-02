package v2

import (
	"fmt"
	"runtime"
)

func main() {
	fmt.Printf("Go version: %s\n", runtime.Version())
	// Output:
	// Go version: go1.14.2
}
