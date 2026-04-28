//go:build !linux
// +build !linux

package hesync

import (
	"fmt"
	"runtime"
)

// writeFileDirect on non-Linux platforms is a stub that returns an error,
// since O_DIRECT is a Linux-specific flag.
func writeFileDirect(path string, data []byte) error {
	return fmt.Errorf("evkstore: O_DIRECT not supported on %s", runtime.GOOS)
}

// readFileDirect on non-Linux platforms is a stub that returns an error.
func readFileDirect(path string) ([]byte, error) {
	return nil, fmt.Errorf("evkstore: O_DIRECT not supported on %s", runtime.GOOS)
}
