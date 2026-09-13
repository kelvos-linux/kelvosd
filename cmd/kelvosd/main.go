package main

import (
	"fmt"
	"os"

	"github.com/kelvosd/kelvosd/internal/cli"
)

const version = "0.2.0"

func main() {
	if err := cli.Execute(version); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
