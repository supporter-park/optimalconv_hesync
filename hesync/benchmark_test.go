package hesync

import (
	"bytes"
	"strings"
	"testing"

	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/supporter-park/optimalconv_hesync/utils"
	"github.com/stretchr/testify/require"
)

func TestRunBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark test in short mode")
	}

	params := testParams()
	kgen := ckks.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rlkKey := kgen.GenRelinearizationKey(sk, 2)
	rotKeys := kgen.GenRotationKeysForRotations([]int{1, 2, 3}, true, sk)
	evk := rlwe.EvaluationKey{Rlk: rlkKey, Rtks: rotKeys}

	prng, _ := utils.NewPRNG()
	ct := ckks.NewCiphertextRandom(prng, params, 1, params.MaxLevel(), params.Scale())

	// Simple workload: MulRelin → Rescale → Rotate
	workload := func(eval ckks.Evaluator, ctIn *ckks.Ciphertext) *ckks.Ciphertext {
		out := ckks.NewCiphertext(params, 1, ctIn.Level(), ctIn.Scale)
		eval.MulRelin(ctIn, ctIn, out)
		if out.Level() > 0 {
			rescaled := ckks.NewCiphertext(params, 1, out.Level(), out.Scale)
			eval.Rescale(out, params.Scale()/2, rescaled)
			out = rescaled
		}
		if out.Level() > 0 {
			rotOut := ckks.NewCiphertext(params, 1, out.Level(), out.Scale)
			eval.Rotate(out, 1, rotOut)
			out = rotOut
		}
		return out
	}

	dir := t.TempDir()
	cfg := BenchmarkConfig{
		Params:       params,
		EvalKey:      evk,
		Criteria:     []PlanCriterion{CriterionPerTrace, CriterionLevel0},
		ProfileIters: 1,
		EVKStoreDir:  dir,
	}

	results, err := RunBenchmark(cfg, workload, ct)
	require.NoError(t, err)
	require.Equal(t, 2, len(results))

	for _, r := range results {
		t.Logf("Criterion=%s: baseline=%v hesync=%v overhead=%.1f%% peakEVKs=%d/%d reduction=%.1f%% stall=%v (%.1f%%)",
			r.Criterion, r.BaselineLatency, r.HESyncLatency, r.Overhead(),
			r.HESyncPeakEVKs, r.BaselinePeakEVKs, r.EVKReduction(),
			r.HESyncStallTime, r.StallPercent())

		// Sanity checks
		require.Greater(t, r.BaselineLatency.Nanoseconds(), int64(0))
		require.Greater(t, r.HESyncLatency.Nanoseconds(), int64(0))
		require.Greater(t, r.BaselinePeakEVKs, 0)
		require.Greater(t, r.HESyncPeakEVKs, 0)
		require.LessOrEqual(t, r.HESyncPeakEVKs, r.BaselinePeakEVKs)
		require.Greater(t, r.TraceLength, 0)
		require.Greater(t, r.DryRunLatency.Nanoseconds(), int64(0))
	}
}

func TestWriteResults(t *testing.T) {
	results := []BenchmarkResult{
		{
			Criterion:        CriterionPerTrace,
			BaselineLatency:  1000000000, // 1s
			BaselinePeakEVKs: 100,
			HESyncLatency:    1010000000, // 1.01s
			HESyncPeakEVKs:   5,
			HESyncStallTime:  10000000, // 10ms
			DryRunLatency:    500000000,
			TraceLength:      200,
			EVKSizeMB:        1.5,
		},
	}

	var buf bytes.Buffer
	WriteResults(&buf, results)
	output := buf.String()

	require.Contains(t, output, "HESync Benchmark Results")
	require.Contains(t, output, "Trace length:")
	require.Contains(t, output, "PerTrace")
	require.Contains(t, output, "Criterion")

	// Check it contains the table
	lines := strings.Split(output, "\n")
	hasDataRow := false
	for _, line := range lines {
		if strings.Contains(line, "PerTrace") {
			hasDataRow = true
		}
	}
	require.True(t, hasDataRow, "output should contain PerTrace data row")
}

func TestBenchmarkResultMetrics(t *testing.T) {
	r := BenchmarkResult{
		BaselineLatency:  1000000000, // 1s
		BaselinePeakEVKs: 100,
		HESyncLatency:    1100000000, // 1.1s
		HESyncPeakEVKs:   10,
		HESyncStallTime:  55000000, // 55ms
	}

	require.InDelta(t, 10.0, r.Overhead(), 0.1)
	require.InDelta(t, 90.0, r.EVKReduction(), 0.1)
	require.InDelta(t, 5.0, r.StallPercent(), 0.1)
}
