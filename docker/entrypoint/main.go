package main

import (
	"fmt"
	"os"
)

func main() {
	launch, err := prepare(environmentSettings(), os.Args[1:])
	if err == nil {
		err = os.Chdir(launch.dir)
	}
	if err == nil {
		err = replaceProcess(launch.path, append([]string{launch.path}, launch.args...), os.Environ())
	}
	fmt.Fprintln(os.Stderr, "Container startup failed:", err)
	os.Exit(1)
}
