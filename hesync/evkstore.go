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
	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return err
	}

	s.index[id] = path
	return nil
}

// Load reads a single SwitchingKey from disk by its identifier.
func (s *EVKStore) Load(id EVKIdentifier) (*rlwe.SwitchingKey, error) {
	path, ok := s.index[id]
	if !ok {
		return nil, fmt.Errorf("evkstore: key not found: %s", id)
	}

	data, err := ioutil.ReadFile(path)
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

// KeySize returns the on-disk byte size of a single stored key.
// Returns 0 if no keys are stored.
func (s *EVKStore) KeySize() int {
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
	return nil
}
