package hesync

import (
	"testing"
	"time"

	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/stretchr/testify/require"
)

// testEvalKey generates a real evaluation key for profiling tests.
func testEvalKey(params ckks.Parameters) (rlwe.EvaluationKey, *rlwe.SecretKey) {
	kgen := ckks.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rlk := kgen.GenRelinearizationKey(sk, 2)
	rotKey := kgen.GenRotationKeysForRotations([]int{1, -1, 5}, true, sk)
	return rlwe.EvaluationKey{Rlk: rlk, Rtks: rotKey}, sk
}

func TestProfilerBasicOps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiler test in short mode")
	}

	params := testParams()
	evk, _ := testEvalKey(params)

	// Create a small trace with diverse operations
	tracer := NewTracingEvaluator(params)
	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	ct1 := newTracerCiphertext(params, 1, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())

	tracer.Add(ct0, ct1, ctOut)
	tracer.MulRelin(ct0, ct1, ctOut)
	tracer.Rotate(ct0, 1, ctOut)

	trace := tracer.GetTrace()

	// Profile the trace
	profiler := NewProfiler(params)
	profiler.SetIterations(1) // Minimize test time
	profile := profiler.ProfileFromTrace(trace, evk, nil)

	require.NotNil(t, profile)
	require.Equal(t, params.MaxLevel(), profile.MaxLevel)

	// Verify that timings were recorded for the operations in the trace
	require.Contains(t, profile.OpTimings, "Add")
	require.Contains(t, profile.OpTimings, "MulRelin")
	require.Contains(t, profile.OpTimings, "Rotate")

	// All timings should be at level 3 (the level we used)
	require.Contains(t, profile.OpTimings["Add"], 3)
	require.Contains(t, profile.OpTimings["MulRelin"], 3)
	require.Contains(t, profile.OpTimings["Rotate"], 3)

	// All durations should be positive
	require.Greater(t, profile.OpTimings["Add"][3].Nanoseconds(), int64(0))
	require.Greater(t, profile.OpTimings["MulRelin"][3].Nanoseconds(), int64(0))
	require.Greater(t, profile.OpTimings["Rotate"][3].Nanoseconds(), int64(0))

	// MulRelin and Rotate should be slower than Add
	require.Greater(t, profile.OpTimings["MulRelin"][3], profile.OpTimings["Add"][3],
		"MulRelin should be slower than Add")
}

func TestProfilerMultipleLevels(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiler test in short mode")
	}

	params := testParams()
	evk, _ := testEvalKey(params)

	// Create a trace with operations at different levels
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 4, params.Scale())
	ct1 := newTracerCiphertext(params, 1, 4, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 4, params.Scale())

	// MulRelin at level 4
	tracer.MulRelin(ct0, ct1, ctOut)

	// Create ciphertext at level 1
	ct2 := newTracerCiphertext(params, 1, 1, params.Scale())
	ct3 := newTracerCiphertext(params, 1, 1, params.Scale())
	ctOut2 := newTracerCiphertext(params, 1, 1, params.Scale())

	// MulRelin at level 1
	tracer.MulRelin(ct2, ct3, ctOut2)

	trace := tracer.GetTrace()

	profiler := NewProfiler(params)
	profiler.SetIterations(1)
	profile := profiler.ProfileFromTrace(trace, evk, nil)

	// Should have timings at both levels
	require.Contains(t, profile.OpTimings["MulRelin"], 4)
	require.Contains(t, profile.OpTimings["MulRelin"], 1)

	// Higher level should be slower (more moduli to process)
	require.Greater(t, profile.OpTimings["MulRelin"][4], profile.OpTimings["MulRelin"][1],
		"MulRelin at level 4 should be slower than at level 1")
}

func TestProfileGetDurationCriteria(t *testing.T) {
	// Test the GetDuration method with different criteria (using synthetic data)
	profile := &Profile{
		OpTimings: map[string]map[int]time.Duration{
			"MulRelin": {
				0: 10 * time.Millisecond,
				2: 20 * time.Millisecond,
				5: 50 * time.Millisecond,
			},
		},
		BootstrapTime: 500 * time.Millisecond,
		MaxLevel:      5,
	}

	entry := TraceEntry{OpType: "MulRelin", InputLevel: 2}

	// CriterionLevel0: should use level 0
	d := profile.GetDuration(entry, CriterionLevel0)
	require.Equal(t, 10*time.Millisecond, d)

	// CriterionHalfMax: maxLevel=5, half=2, should use level 2
	d = profile.GetDuration(entry, CriterionHalfMax)
	require.Equal(t, 20*time.Millisecond, d)

	// CriterionMaxLevel: should use level 5
	d = profile.GetDuration(entry, CriterionMaxLevel)
	require.Equal(t, 50*time.Millisecond, d)

	// CriterionPerTrace: entry.InputLevel=2, should use level 2
	d = profile.GetDuration(entry, CriterionPerTrace)
	require.Equal(t, 20*time.Millisecond, d)
}

func TestProfileGetDurationBootstrap(t *testing.T) {
	profile := &Profile{
		OpTimings:     map[string]map[int]time.Duration{},
		BootstrapTime: 500 * time.Millisecond,
		MaxLevel:      5,
	}

	entry := TraceEntry{OpType: "Bootstrap", InputLevel: 0}
	d := profile.GetDuration(entry, CriterionPerTrace)
	require.Equal(t, 500*time.Millisecond, d)
}

func TestProfileGetDurationFallback(t *testing.T) {
	// Test fallback to closest level when exact level is missing
	profile := &Profile{
		OpTimings: map[string]map[int]time.Duration{
			"Add": {
				0: 5 * time.Millisecond,
				4: 20 * time.Millisecond,
			},
		},
		MaxLevel: 5,
	}

	// CriterionPerTrace at level 3: no exact match, should fall back to closest (4)
	entry := TraceEntry{OpType: "Add", InputLevel: 3}
	d := profile.GetDuration(entry, CriterionPerTrace)
	require.Equal(t, 20*time.Millisecond, d)

	// CriterionPerTrace at level 1: closest is 0
	entry = TraceEntry{OpType: "Add", InputLevel: 1}
	d = profile.GetDuration(entry, CriterionPerTrace)
	require.Equal(t, 5*time.Millisecond, d)
}

func TestProfileSetBootstrapTime(t *testing.T) {
	profile := &Profile{
		OpTimings: make(map[string]map[int]time.Duration),
	}
	require.Equal(t, time.Duration(0), profile.BootstrapTime)

	profile.SetBootstrapTime(1234 * time.Millisecond)
	require.Equal(t, 1234*time.Millisecond, profile.BootstrapTime)
}

func TestProfilerWithEVKStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiler test in short mode")
	}

	params := testParams()
	evk, _ := testEvalKey(params)

	// Create an EVKStore with keys
	dir := t.TempDir()
	store, err := NewEVKStore(dir)
	require.NoError(t, err)
	err = store.SaveAll(evk.Rlk, evk.Rtks)
	require.NoError(t, err)

	// Create a minimal trace
	tracer := NewTracingEvaluator(params)
	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	ct1 := newTracerCiphertext(params, 1, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())
	tracer.Add(ct0, ct1, ctOut)
	trace := tracer.GetTrace()

	profiler := NewProfiler(params)
	profiler.SetIterations(1)
	profile := profiler.ProfileFromTrace(trace, evk, store)

	// EVKLoadTime should be measured
	require.Greater(t, profile.EVKLoadTime.Nanoseconds(), int64(0),
		"EVK load latency should be positive when store is provided")
}
