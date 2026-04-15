package hesync

import (
	"sync"

	"github.com/supporter-park/optimalconv_hesync/rlwe"
)

// EVKContainer is a thread-safe, mutable container for evaluation keys.
// It is shared between the evaluator (reader) and the Prefetcher (writer).
// The evaluator's RotationKeySet and RelinearizationKey fields point directly
// to this container's key sets, so mutations here are visible to the evaluator.
type EVKContainer struct {
	mu           sync.RWMutex
	rtks         *rlwe.RotationKeySet
	rlk          *rlwe.RelinearizationKey
	currentCount int
	peakCount    int
}

// NewEVKContainer creates a new empty EVK container.
func NewEVKContainer() *EVKContainer {
	return &EVKContainer{
		rtks: &rlwe.RotationKeySet{
			Keys: make(map[uint64]*rlwe.SwitchingKey),
		},
		rlk: &rlwe.RelinearizationKey{
			Keys: make([]*rlwe.SwitchingKey, 1),
		},
	}
}

// RotationKeySet returns the container's RotationKeySet for sharing with an evaluator.
func (c *EVKContainer) RotationKeySet() *rlwe.RotationKeySet {
	return c.rtks
}

// RelinearizationKey returns the container's RelinearizationKey for sharing with an evaluator.
func (c *EVKContainer) RelinearizationKey() *rlwe.RelinearizationKey {
	return c.rlk
}

// Put inserts an EVK into the container. Thread-safe.
func (c *EVKContainer) Put(id EVKIdentifier, key *rlwe.SwitchingKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch id.Type {
	case RelinKey:
		if c.rlk.Keys[0] == nil {
			c.currentCount++
		}
		c.rlk.Keys[0] = key
	case RotationKey:
		if _, exists := c.rtks.Keys[id.GaloisEl]; !exists {
			c.currentCount++
		}
		c.rtks.Keys[id.GaloisEl] = key
	}

	if c.currentCount > c.peakCount {
		c.peakCount = c.currentCount
	}
}

// Remove removes an EVK from the container. Thread-safe.
func (c *EVKContainer) Remove(id EVKIdentifier) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch id.Type {
	case RelinKey:
		if c.rlk.Keys[0] != nil {
			c.rlk.Keys[0] = nil
			c.currentCount--
		}
	case RotationKey:
		if _, exists := c.rtks.Keys[id.GaloisEl]; exists {
			delete(c.rtks.Keys, id.GaloisEl)
			c.currentCount--
		}
	}
}

// Has returns true if the container has the given EVK.
func (c *EVKContainer) Has(id EVKIdentifier) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch id.Type {
	case RelinKey:
		return c.rlk.Keys[0] != nil
	case RotationKey:
		_, exists := c.rtks.Keys[id.GaloisEl]
		return exists
	}
	return false
}

// PeakCount returns the maximum number of EVKs simultaneously present.
func (c *EVKContainer) PeakCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.peakCount
}

// CurrentCount returns the current number of EVKs in the container.
func (c *EVKContainer) CurrentCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentCount
}

// Reset clears all keys and resets counters.
func (c *EVKContainer) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.rtks.Keys = make(map[uint64]*rlwe.SwitchingKey)
	c.rlk.Keys[0] = nil
	c.currentCount = 0
	c.peakCount = 0
}
