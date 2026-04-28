//go:build linux
// +build linux

package hesync

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

// directIOAlign is the alignment required by the kernel for O_DIRECT I/O on
// virtually all Linux filesystems (logical block size; tmpfs does not support
// O_DIRECT at all). 4096 bytes is safe for ext4/xfs/btrfs on standard storage.
const directIOAlign = 4096

// directIOHeaderLen is the on-disk header that records the original payload
// length (since the file is padded out to a block boundary).
const directIOHeaderLen = 8

// alignedBuf returns a byte slice of exactly `size` bytes whose backing
// storage starts on a `directIOAlign`-byte boundary. The returned slice
// references heap memory allocated by `make`, which the Go runtime does not
// move (Go's GC is non-moving), so the alignment is stable for syscalls.
func alignedBuf(size int) []byte {
	if size == 0 {
		return nil
	}
	raw := make([]byte, size+directIOAlign)
	addr := uintptr(unsafe.Pointer(&raw[0]))
	off := int((directIOAlign - addr%directIOAlign) % directIOAlign)
	return raw[off : off+size : off+size]
}

// roundUpAlign returns n rounded up to the next multiple of directIOAlign.
func roundUpAlign(n int) int {
	return (n + directIOAlign - 1) &^ (directIOAlign - 1)
}

// writeFileDirect writes data to path using O_DIRECT, bypassing the OS page
// cache. The file layout is:
//
//	[8-byte little-endian payload length][payload bytes][zero padding to block boundary]
func writeFileDirect(path string, data []byte) error {
	totalLogical := directIOHeaderLen + len(data)
	totalPadded := roundUpAlign(totalLogical)

	buf := alignedBuf(totalPadded)
	binary.LittleEndian.PutUint64(buf[:directIOHeaderLen], uint64(len(data)))
	copy(buf[directIOHeaderLen:], data)
	// Tail beyond `totalLogical` is already zero (make-allocated).

	fd, err := syscall.Open(path,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_DIRECT,
		0644)
	if err != nil {
		return fmt.Errorf("evkstore: open O_DIRECT %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	written := 0
	for written < totalPadded {
		n, err := syscall.Write(fd, buf[written:])
		if err != nil {
			return fmt.Errorf("evkstore: write O_DIRECT %s: %w", path, err)
		}
		if n <= 0 {
			return fmt.Errorf("evkstore: write O_DIRECT %s: zero-byte write", path)
		}
		written += n
	}
	return nil
}

// readFileDirect reads a file written by writeFileDirect using O_DIRECT and
// returns the original (unpadded) payload bytes.
func readFileDirect(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECT, 0)
	if err != nil {
		return nil, fmt.Errorf("evkstore: open O_DIRECT %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("evkstore: stat O_DIRECT %s: %w", path, err)
	}
	totalPadded := int(info.Size())
	if totalPadded%directIOAlign != 0 {
		return nil, fmt.Errorf("evkstore: %s size %d not aligned to %d",
			path, totalPadded, directIOAlign)
	}
	if totalPadded < directIOAlign {
		return nil, fmt.Errorf("evkstore: %s too small (%d bytes)", path, totalPadded)
	}

	buf := alignedBuf(totalPadded)
	read := 0
	for read < totalPadded {
		n, err := syscall.Read(fd, buf[read:])
		if err != nil {
			return nil, fmt.Errorf("evkstore: read O_DIRECT %s: %w", path, err)
		}
		if n == 0 {
			return nil, fmt.Errorf("evkstore: read O_DIRECT %s: %w", path, io.ErrUnexpectedEOF)
		}
		read += n
	}

	payloadLen := int(binary.LittleEndian.Uint64(buf[:directIOHeaderLen]))
	if payloadLen < 0 || directIOHeaderLen+payloadLen > totalPadded {
		return nil, fmt.Errorf("evkstore: %s corrupt header (len=%d, file=%d)",
			path, payloadLen, totalPadded)
	}

	// Copy out so we don't pin the oversized aligned buffer.
	out := make([]byte, payloadLen)
	copy(out, buf[directIOHeaderLen:directIOHeaderLen+payloadLen])
	return out, nil
}
