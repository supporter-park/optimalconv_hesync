package hesync

import (
	"os"
	"testing"

	"github.com/supporter-park/optimalconv_hesync/ring"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/stretchr/testify/require"
)

// newTestSwitchingKey creates a small SwitchingKey for testing.
// decomposition is the number of RNS components, N is the ring degree, levels is the number of moduli.
func newTestSwitchingKey(decomposition, N, levels int) *rlwe.SwitchingKey {
	swk := &rlwe.SwitchingKey{
		Value: make([][2]*ring.Poly, decomposition),
	}
	for i := 0; i < decomposition; i++ {
		swk.Value[i][0] = ring.NewPoly(N, levels)
		swk.Value[i][1] = ring.NewPoly(N, levels)
		// Fill with non-zero data so round-trip is meaningful
		for j := 0; j < levels; j++ {
			for k := 0; k < N; k++ {
				swk.Value[i][0].Coeffs[j][k] = uint64(i*1000 + j*100 + k)
				swk.Value[i][1].Coeffs[j][k] = uint64(i*1000 + j*100 + k + 1)
			}
		}
	}
	return swk
}

func TestEVKStoreSaveLoadRoundTrip(t *testing.T) {
	dir, err := os.MkdirTemp("", "evkstore_test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	store, err := NewEVKStore(dir)
	require.NoError(t, err)

	// Create a small relin key and rotation key set
	N := 16
	levels := 3
	decomp := 2

	rlk := &rlwe.RelinearizationKey{
		Keys: []*rlwe.SwitchingKey{newTestSwitchingKey(decomp, N, levels)},
	}

	rtks := &rlwe.RotationKeySet{
		Keys: map[uint64]*rlwe.SwitchingKey{
			5:  newTestSwitchingKey(decomp, N, levels),
			17: newTestSwitchingKey(decomp, N, levels),
		},
	}

	// Save all keys
	err = store.SaveAll(rlk, rtks)
	require.NoError(t, err)

	// Verify count: 1 relin + 2 rotation = 3
	require.Equal(t, 3, store.Count())

	// Load relin key and verify round-trip
	relinID := EVKIdentifier{Type: RelinKey, GaloisEl: 0}
	loadedRelin, err := store.Load(relinID)
	require.NoError(t, err)
	require.True(t, rlk.Keys[0].Equals(loadedRelin),
		"relin key round-trip mismatch")

	// Load rotation keys and verify round-trip
	for galEl, origSwk := range rtks.Keys {
		rotID := EVKIdentifier{Type: RotationKey, GaloisEl: galEl}
		loadedRot, err := store.Load(rotID)
		require.NoError(t, err)
		require.True(t, origSwk.Equals(loadedRot),
			"rotation key %d round-trip mismatch", galEl)
	}
}

func TestEVKStoreLoadNonexistent(t *testing.T) {
	dir, err := os.MkdirTemp("", "evkstore_test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	store, err := NewEVKStore(dir)
	require.NoError(t, err)

	_, err = store.Load(EVKIdentifier{Type: RotationKey, GaloisEl: 999})
	require.Error(t, err)
}

func TestEVKStoreKeySize(t *testing.T) {
	dir, err := os.MkdirTemp("", "evkstore_test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	store, err := NewEVKStore(dir)
	require.NoError(t, err)

	// No keys stored yet
	require.Equal(t, 0, store.KeySize())

	rlk := &rlwe.RelinearizationKey{
		Keys: []*rlwe.SwitchingKey{newTestSwitchingKey(2, 16, 3)},
	}
	err = store.SaveAll(rlk, nil)
	require.NoError(t, err)

	size := store.KeySize()
	require.Greater(t, size, 0)
}

func TestEVKStoreLoadLatency(t *testing.T) {
	dir, err := os.MkdirTemp("", "evkstore_test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	store, err := NewEVKStore(dir)
	require.NoError(t, err)

	// No keys stored — should return 0
	require.Equal(t, store.LoadLatency(), 0*store.LoadLatency())

	rlk := &rlwe.RelinearizationKey{
		Keys: []*rlwe.SwitchingKey{newTestSwitchingKey(2, 16, 3)},
	}
	err = store.SaveAll(rlk, nil)
	require.NoError(t, err)

	latency := store.LoadLatency()
	require.Greater(t, latency.Nanoseconds(), int64(0))
}

func TestEVKStoreAllIDs(t *testing.T) {
	dir, err := os.MkdirTemp("", "evkstore_test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	store, err := NewEVKStore(dir)
	require.NoError(t, err)

	rtks := &rlwe.RotationKeySet{
		Keys: map[uint64]*rlwe.SwitchingKey{
			5:  newTestSwitchingKey(2, 16, 3),
			17: newTestSwitchingKey(2, 16, 3),
			33: newTestSwitchingKey(2, 16, 3),
		},
	}
	err = store.SaveAll(nil, rtks)
	require.NoError(t, err)

	ids := store.AllIDs()
	require.Equal(t, 3, len(ids))

	galEls := make(map[uint64]bool)
	for _, id := range ids {
		require.Equal(t, RotationKey, id.Type)
		galEls[id.GaloisEl] = true
	}
	require.True(t, galEls[5])
	require.True(t, galEls[17])
	require.True(t, galEls[33])
}

func TestEVKStoreCleanup(t *testing.T) {
	dir, err := os.MkdirTemp("", "evkstore_test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	store, err := NewEVKStore(dir)
	require.NoError(t, err)

	rlk := &rlwe.RelinearizationKey{
		Keys: []*rlwe.SwitchingKey{newTestSwitchingKey(2, 16, 3)},
	}
	err = store.SaveAll(rlk, nil)
	require.NoError(t, err)
	require.Equal(t, 1, store.Count())

	err = store.Cleanup()
	require.NoError(t, err)
	require.Equal(t, 0, store.Count())
}

func TestEVKStoreDirectIORoundTrip(t *testing.T) {
	dir, err := os.MkdirTemp("", "evkstore_directio_test")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	store, err := NewEVKStore(dir)
	require.NoError(t, err)
	store.EnableDirectIO()
	require.True(t, store.DirectIOEnabled())

	// Use a payload large enough to exercise multi-block writes (>4 KiB)
	// and small enough to keep the test fast.
	N := 1024
	levels := 4
	decomp := 3

	rlk := &rlwe.RelinearizationKey{
		Keys: []*rlwe.SwitchingKey{newTestSwitchingKey(decomp, N, levels)},
	}

	rtks := &rlwe.RotationKeySet{
		Keys: map[uint64]*rlwe.SwitchingKey{
			5:  newTestSwitchingKey(decomp, N, levels),
			17: newTestSwitchingKey(decomp, N, levels),
		},
	}

	err = store.SaveAll(rlk, rtks)
	require.NoError(t, err)
	require.Equal(t, 3, store.Count())

	// KeySize should report the logical (unpadded) payload size, not the
	// on-disk padded size.
	rawBytes, err := rlk.Keys[0].MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, len(rawBytes), store.KeySize())

	// Round-trip relin key.
	relinID := EVKIdentifier{Type: RelinKey, GaloisEl: 0}
	loadedRelin, err := store.Load(relinID)
	require.NoError(t, err)
	require.True(t, rlk.Keys[0].Equals(loadedRelin),
		"relin key direct-IO round-trip mismatch")

	// Round-trip rotation keys.
	for galEl, origSwk := range rtks.Keys {
		rotID := EVKIdentifier{Type: RotationKey, GaloisEl: galEl}
		loadedRot, err := store.Load(rotID)
		require.NoError(t, err)
		require.True(t, origSwk.Equals(loadedRot),
			"rotation key %d direct-IO round-trip mismatch", galEl)
	}

	// On-disk file size must be a multiple of the alignment.
	for _, id := range store.AllIDs() {
		info, err := os.Stat(store.index[id])
		require.NoError(t, err)
		require.Equal(t, int64(0), info.Size()%4096,
			"file %s size %d not aligned", id, info.Size())
	}
}

func TestEVKIdentifierString(t *testing.T) {
	require.Equal(t, "relin_0", EVKIdentifier{Type: RelinKey}.String())
	require.Equal(t, "rot_42", EVKIdentifier{Type: RotationKey, GaloisEl: 42}.String())
}
