package cmd

import (
	"fmt"
	"os"
)

// `fatal` Prints out what we can from the underlying error
// and quits the tool with a non-zero status code.
func fatal(err error) {
	fmt.Printf("ERROR: %s\n", err)
	os.Exit(1)
}
