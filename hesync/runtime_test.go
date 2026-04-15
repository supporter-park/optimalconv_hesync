package hesync

import (
	"testing"

	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/supporter-park/optimalconv_hesync/utils"
	"github.com/stretchr/testify/require"
)

func TestEVKContainerPutRemove(t *testing.T) {
	container := NewEVKContainer()

	swk := newTestSwitchingKey(2, 16, 3)
	rotID := EVKIdentifier{Type: RotationKey, GaloisEl: 5}
	relinID := EVKIdentifier{Type: RelinKey, GaloisEl: 0}

	// Initially empty
	require.Equal(t, 0, container.CurrentCount())
	require.False(t, container.Has(rotID))

	// Put rotation key
	container.Put(rotID, swk)
	require.Equal(t, 1, container.CurrentCount())
	require.Equal(t, 1, container.PeakCount())
	require.True(t, container.Has(rotID))

	// Put relin key
	container.Put(relinID, swk)
	require.Equal(t, 2, container.CurrentCount())
	require.Equal(t, 2, container.PeakCount())

	// Remove rotation key
	container.Remove(rotID)
	require.Equal(t, 1, container.CurrentCount())
	require.Equal(t, 2, container.PeakCount()) // peak unchanged

	// Remove relin key
	container.Remove(relinID)
	require.Equal(t, 0, container.CurrentCount())

	// Double remove is safe
	container.Remove(rotID)
	require.Equal(t, 0, container.CurrentCount())
}

func TestEVKContainerSharedReference(t *testing.T) {
	container := NewEVKContainer()

	// The evaluator would hold references to these
	rtks := container.RotationKeySet()
	rlk := container.RelinearizationKey()

	swk := newTestSwitchingKey(2, 16, 3)

	// Put via container
	container.Put(EVKIdentifier{Type: RotationKey, GaloisEl: 5}, swk)

	// Visible via shared reference
	_, exists := rtks.Keys[5]
	require.True(t, exists, "key should be visible through shared RotationKeySet reference")

	container.Put(EVKIdentifier{Type: RelinKey}, swk)
	require.NotNil(t, rlk.Keys[0], "relin key should be visible through shared reference")

	// Remove via container
	container.Remove(EVKIdentifier{Type: RotationKey, GaloisEl: 5})
	_, exists = rtks.Keys[5]
	require.False(t, exists, "key should be removed from shared reference")
}

func TestEVKContainerReset(t *testing.T) {
	container := NewEVKContainer()
	swk := newTestSwitchingKey(2, 16, 3)

	container.Put(EVKIdentifier{Type: RotationKey, GaloisEl: 5}, swk)
	container.Put(EVKIdentifier{Type: RelinKey}, swk)
	require.Equal(t, 2, container.CurrentCount())

	container.Reset()
	require.Equal(t, 0, container.CurrentCount())
	require.Equal(t, 0, container.PeakCount())
}

// TestHESyncEndToEnd tests the full pipeline: Trace → Profile → Plan → Runtime
// and verifies that the HESync evaluator produces the same result as the baseline.
func TestHESyncEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}

	params := testParams() // PN13QP218: logN=13, 6 Q moduli
	kgen := ckks.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rlkKey := kgen.GenRelinearizationKey(sk, 2)
	rotKeys := kgen.GenRotationKeysForRotations([]int{1, -1, 5}, true, sk)
	evk := rlwe.EvaluationKey{Rlk: rlkKey, Rtks: rotKeys}

	encoder := ckks.NewEncoder(params)
	encryptor := ckks.NewEncryptor(params, sk)
	decryptor := ckks.NewDecryptor(params, sk)

	// Create test data
	values := make([]complex128, params.Slots())
	for i := range values {
		values[i] = complex(float64(i)/float64(params.Slots()), 0)
	}
	pt := encoder.EncodeNew(values, params.LogSlots())
	ct := encryptor.EncryptNew(pt)

	// === Baseline: run operations with all keys in memory ===
	baselineEval := ckks.NewEvaluator(params, evk)
	baselineOut := ckks.NewCiphertext(params, 1, ct.Level(), ct.Scale)
	baselineEval.MulRelin(ct, ct, baselineOut)
	baselineEval.Rescale(baselineOut, params.Scale()/2, baselineOut)
	baselineRotOut := ckks.NewCiphertext(params, 1, baselineOut.Level(), baselineOut.Scale)
	baselineEval.Rotate(baselineOut, 1, baselineRotOut)

	baselineResult := encoder.Decode(decryptor.DecryptNew(baselineRotOut), params.LogSlots())

	// === HESync pipeline ===

	// Step 1: Trace
	tracer := NewTracingEvaluator(params)
	tracerCt := newTracerCiphertext(params, 1, ct.Level(), ct.Scale)
	tracerOut := newTracerCiphertext(params, 1, ct.Level(), ct.Scale)
	tracer.MulRelin(tracerCt, tracerCt, tracerOut)
	tracer.Rescale(tracerOut, params.Scale()/2, tracerOut)
	tracerRotOut := newTracerCiphertext(params, 1, tracerOut.Level(), tracerOut.Scale)
	tracer.Rotate(tracerOut, 1, tracerRotOut)
	trace := tracer.GetTrace()

	// Step 2: Save keys to disk
	dir := t.TempDir()
	store, err := NewEVKStore(dir)
	require.NoError(t, err)
	err = store.SaveAll(rlkKey, rotKeys)
	require.NoError(t, err)

	// Step 3: Profile
	profiler := NewProfiler(params)
	profiler.SetIterations(1)
	profile := profiler.ProfileFromTrace(trace, evk, store)

	// Step 4: Plan
	plan := GeneratePlan(trace, profile, CriterionPerTrace)
	require.Equal(t, len(trace.Entries), len(plan.Instructions))

	// Step 5: Runtime — set up container, evaluator, prefetcher
	container := NewEVKContainer()

	// Create evaluator with container's shared key references
	innerEval := ckks.NewEvaluator(params, rlwe.EvaluationKey{
		Rlk:  container.RelinearizationKey(),
		Rtks: container.RotationKeySet(),
	})

	// Pre-compute NTT indexes for all rotation keys we'll need
	var galEls []uint64
	for galEl := range rotKeys.Keys {
		galEls = append(galEls, galEl)
	}
	innerEval.PreparePermuteNTTIndex(galEls)

	prefetcher := NewPrefetcher(plan, store, container)
	hesyncEval := NewHESyncEvaluator(innerEval, prefetcher)

	// Run the same operations through HESync evaluator
	hesyncOut := ckks.NewCiphertext(params, 1, ct.Level(), ct.Scale)
	hesyncEval.MulRelin(ct, ct, hesyncOut)
	hesyncEval.Rescale(hesyncOut, params.Scale()/2, hesyncOut)
	hesyncRotOut := ckks.NewCiphertext(params, 1, hesyncOut.Level(), hesyncOut.Scale)
	hesyncEval.Rotate(hesyncOut, 1, hesyncRotOut)

	hesyncResult := encoder.Decode(decryptor.DecryptNew(hesyncRotOut), params.LogSlots())

	// === Verify results match ===
	t.Logf("Baseline: level=%d scale=%e", baselineRotOut.Level(), baselineRotOut.Scale)
	t.Logf("HESync:   level=%d scale=%e", hesyncRotOut.Level(), hesyncRotOut.Scale)
	t.Logf("Peak EVKs: %d, Stall: %v", container.PeakCount(), prefetcher.StallTime())

	require.Equal(t, len(baselineResult), len(hesyncResult))
	for i := range baselineResult {
		diffR := real(baselineResult[i]) - real(hesyncResult[i])
		diffI := imag(baselineResult[i]) - imag(hesyncResult[i])
		if diffR < 0 {
			diffR = -diffR
		}
		if diffI < 0 {
			diffI = -diffI
		}
		require.Less(t, diffR, 1e-3,
			"real part mismatch at slot %d: baseline=%v hesync=%v", i, baselineResult[i], hesyncResult[i])
		require.Less(t, diffI, 1e-3,
			"imag part mismatch at slot %d: baseline=%v hesync=%v", i, baselineResult[i], hesyncResult[i])
	}

	// Verify EVK management metrics
	require.Greater(t, container.PeakCount(), 0, "should have loaded some EVKs")
	require.LessOrEqual(t, container.PeakCount(), store.Count(),
		"peak EVKs should not exceed total stored")
}

func TestHESyncPeakEVKReduction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping peak EVK test in short mode")
	}

	params := testParams()
	kgen := ckks.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rlkKey := kgen.GenRelinearizationKey(sk, 2)
	// Generate many rotation keys
	rots := []int{1, 2, 3, 4, 5, 6, 7, 8}
	rotKeys := kgen.GenRotationKeysForRotations(rots, true, sk)

	prng, _ := utils.NewPRNG()
	ct := ckks.NewCiphertextRandom(prng, params, 1, params.MaxLevel(), params.Scale())

	// Build a trace where each rotation key is used exactly once, in sequence
	tracer := NewTracingEvaluator(params)
	tracerCt := newTracerCiphertext(params, 1, params.MaxLevel(), params.Scale())
	tracerOut := newTracerCiphertext(params, 1, params.MaxLevel(), params.Scale())

	for _, k := range rots {
		tracer.Rotate(tracerCt, k, tracerOut)
	}
	trace := tracer.GetTrace()

	dir := t.TempDir()
	store, err := NewEVKStore(dir)
	require.NoError(t, err)
	err = store.SaveAll(rlkKey, rotKeys)
	require.NoError(t, err)

	totalKeys := store.Count() // 1 relin + 8 rotation = 9

	// Profile and plan
	evk := rlwe.EvaluationKey{Rlk: rlkKey, Rtks: rotKeys}
	profiler := NewProfiler(params)
	profiler.SetIterations(1)
	profile := profiler.ProfileFromTrace(trace, evk, store)
	plan := GeneratePlan(trace, profile, CriterionPerTrace)

	// Runtime
	container := NewEVKContainer()
	innerEval := ckks.NewEvaluator(params, rlwe.EvaluationKey{
		Rlk:  container.RelinearizationKey(),
		Rtks: container.RotationKeySet(),
	})
	var galEls []uint64
	for galEl := range rotKeys.Keys {
		galEls = append(galEls, galEl)
	}
	innerEval.PreparePermuteNTTIndex(galEls)

	prefetcher := NewPrefetcher(plan, store, container)
	hesyncEval := NewHESyncEvaluator(innerEval, prefetcher)

	ctOut := ckks.NewCiphertext(params, 1, ct.Level(), ct.Scale)
	for _, k := range rots {
		hesyncEval.Rotate(ct, k, ctOut)
	}

	// With sequential single-use rotations and aggressive freeing,
	// peak EVKs should be less than total keys
	peakEVKs := container.PeakCount()
	t.Logf("Total keys: %d, Peak EVKs in container: %d", totalKeys, peakEVKs)
	require.Less(t, peakEVKs, totalKeys,
		"HESync should reduce peak EVK count below total")
}

func TestPrefetcherStallTime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stall time test in short mode")
	}

	params := testParams()
	kgen := ckks.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rlkKey := kgen.GenRelinearizationKey(sk, 2)
	rotKeys := kgen.GenRotationKeysForRotations([]int{1}, true, sk)

	dir := t.TempDir()
	store, err := NewEVKStore(dir)
	require.NoError(t, err)
	err = store.SaveAll(rlkKey, rotKeys)
	require.NoError(t, err)

	// Create a plan where Fetch and Sync are at the same position (guaranteed stall)
	rotEVK := EVKIdentifier{Type: RotationKey, GaloisEl: params.GaloisElementForColumnRotationBy(1)}
	trace := &Trace{
		Entries: []TraceEntry{
			{OpIndex: 0, OpType: "Rotate", InputLevel: 3, OutputLevel: 3, EVKs: []EVKIdentifier{rotEVK}},
		},
	}
	plan := &Plan{
		Instructions: []PlanInstruction{
			{FetchEVKs: []EVKIdentifier{rotEVK}, SyncEVKs: []EVKIdentifier{rotEVK}},
		},
		Trace: trace,
	}

	container := NewEVKContainer()
	prefetcher := NewPrefetcher(plan, store, container)

	// HandleInstruction should cause a stall (fetch + immediate sync)
	prefetcher.HandleInstruction(0)

	// Stall time should be > 0 since we waited for the load
	require.Greater(t, prefetcher.StallTime().Nanoseconds(), int64(0),
		"should have measurable stall time when Fetch and Sync are at same position")

	// The key should now be in the container
	require.True(t, container.Has(rotEVK))
}
