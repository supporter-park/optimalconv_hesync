package hesync

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/supporter-park/optimalconv_hesync/rlwe"
)

// EVKStore manages individual SwitchingKey serialization to/from disk.
// Each key is stored as a separate file, enabling on-demand loading.
type EVKStore struct {
	dir   string
	index map[EVKIdentifier]string // ID -> absolute file path

	// useDirectIO, when true, opens key files with O_DIRECT so reads and writes
	// bypass the OS page cache. This avoids polluting DRAM with EVK bytes that
	// will not be reused, at the cost of stricter alignment requirements
	// (handled internally).
	useDirectIO bool

	// keyDataLen is the logical (unpadded) size of a single serialized key.
	// Recorded at first save; used by KeySize when O_DIRECT padding makes the
	// on-disk file size larger than the actual payload.
	keyDataLen int
}

// NewEVKStore creates a new EVKStore backed by the given directory.
// The directory is created if it does not exist.
func NewEVKStore(dir string) (*EVKStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("evkstore: create dir: %w", err)
	}
	return &EVKStore{
		dir:   dir,
		index: make(map[EVKIdentifier]string),
	}, nil
}

// EnableDirectIO switches the store to use O_DIRECT for all subsequent
// SaveAll/Load calls. This bypasses the OS page cache so EVK bytes do not
// linger in DRAM after use. Only supported on Linux; on other platforms,
// subsequent writes/reads will fail with a clear error.
//
// Must be called before SaveAll. Toggling between modes for the same store
// is not supported (existing files written in the other mode will not be
// readable).
func (s *EVKStore) EnableDirectIO() {
	s.useDirectIO = true
}

// DirectIOEnabled reports whether O_DIRECT is in use.
func (s *EVKStore) DirectIOEnabled() bool {
	return s.useDirectIO
}

// SaveAll serializes all evaluation keys to disk as individual files.
// Each SwitchingKey in the RelinearizationKey and RotationKeySet is stored separately.
func (s *EVKStore) SaveAll(rlk *rlwe.RelinearizationKey, rtks *rlwe.RotationKeySet) error {
	// Save relinearization key(s)
	if rlk != nil {
		for i, swk := range rlk.Keys {
			if swk == nil {
				continue
			}
			id := EVKIdentifier{Type: RelinKey, GaloisEl: uint64(i)}
			if err := s.saveKey(id, swk); err != nil {
				return fmt.Errorf("evkstore: save relin key %d: %w", i, err)
			}
		}
	}

	// Save rotation keys
	if rtks != nil {
		for galEl, swk := range rtks.Keys {
			if swk == nil {
				continue
			}
			id := EVKIdentifier{Type: RotationKey, GaloisEl: galEl}
			if err := s.saveKey(id, swk); err != nil {
				return fmt.Errorf("evkstore: save rotation key %d: %w", galEl, err)
			}
		}
	}

	return nil
}

func (s *EVKStore) saveKey(id EVKIdentifier, swk *rlwe.SwitchingKey) error {
	data, err := swk.MarshalBinary()
	if err != nil {
		return err
	}

	path := filepath.Join(s.dir, id.Filename())
	if err := s.writeFile(path, data); err != nil {
		return err
	}

	if s.keyDataLen == 0 {
		s.keyDataLen = len(data)
	}
	s.index[id] = path
	return nil
}

// writeFile dispatches to the direct-I/O path or the regular buffered path.
func (s *EVKStore) writeFile(path string, data []byte) error {
	if s.useDirectIO {
		return writeFileDirect(path, data)
	}
	return ioutil.WriteFile(path, data, 0644)
}

// readFile dispatches to the direct-I/O path or the regular buffered path.
func (s *EVKStore) readFile(path string) ([]byte, error) {
	if s.useDirectIO {
		return readFileDirect(path)
	}
	return ioutil.ReadFile(path)
}

// Load reads a single SwitchingKey from disk by its identifier.
func (s *EVKStore) Load(id EVKIdentifier) (*rlwe.SwitchingKey, error) {
	path, ok := s.index[id]
	if !ok {
		return nil, fmt.Errorf("evkstore: key not found: %s", id)
	}

	data, err := s.readFile(path)
	if err != nil {
		return nil, fmt.Errorf("evkstore: read %s: %w", id, err)
	}

	swk := new(rlwe.SwitchingKey)
	if err := swk.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("evkstore: unmarshal %s: %w", id, err)
	}

	return swk, nil
}

// LoadLatency measures the average time to load a single key from disk.
// It loads an arbitrary stored key 5 times and returns the mean duration.
// Returns 0 if no keys are stored.
func (s *EVKStore) LoadLatency() time.Duration {
	// Pick an arbitrary key from the index
	var id EVKIdentifier
	found := false
	for k := range s.index {
		id = k
		found = true
		break
	}
	if !found {
		return 0
	}

	const trials = 5
	var total time.Duration
	for i := 0; i < trials; i++ {
		start := time.Now()
		_, err := s.Load(id)
		elapsed := time.Since(start)
		if err != nil {
			continue
		}
		total += elapsed
	}

	return total / trials
}

// KeySize returns the logical byte size of a single stored key.
// Returns 0 if no keys are stored.
//
// In direct-I/O mode the on-disk file is padded up to a block boundary;
// this method returns the unpadded payload size recorded at save time.
func (s *EVKStore) KeySize() int {
	if s.useDirectIO {
		return s.keyDataLen
	}
	for _, path := range s.index {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		return int(info.Size())
	}
	return 0
}

// AllIDs returns all stored EVK identifiers.
func (s *EVKStore) AllIDs() []EVKIdentifier {
	ids := make([]EVKIdentifier, 0, len(s.index))
	for id := range s.index {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of stored keys.
func (s *EVKStore) Count() int {
	return len(s.index)
}

// Dir returns the storage directory path.
func (s *EVKStore) Dir() string {
	return s.dir
}

// Cleanup removes all stored key files and clears the index.
func (s *EVKStore) Cleanup() error {
	for id, path := range s.index {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("evkstore: remove %s: %w", id, err)
		}
	}
	s.index = make(map[EVKIdentifier]string)
	s.keyDataLen = 0
	return nil
}
