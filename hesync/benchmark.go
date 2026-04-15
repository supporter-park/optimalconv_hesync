package hesync

import (
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
)

// Workload is a function that runs HE operations using the given evaluator.
// It is called for both baseline and HESync runs.
// The ciphertext argument is the encrypted input data.
type Workload func(eval ckks.Evaluator, ct *ckks.Ciphertext) *ckks.Ciphertext

// BenchmarkConfig configures a HESync benchmark run.
type BenchmarkConfig struct {
	Params          ckks.Parameters
	EvalKey         rlwe.EvaluationKey
	Criteria        []PlanCriterion // Which plan criteria to benchmark
	ProfileIters    int             // Profiler iterations (default 3)
	EVKStoreDir     string          // Directory for EVK storage
}

// BenchmarkResult holds the results of a single benchmark run.
type BenchmarkResult struct {
	Criterion        PlanCriterion
	BaselineLatency  time.Duration
	BaselinePeakEVKs int
	BaselinePeakMem  float64 // MB
	HESyncLatency    time.Duration
	HESyncPeakEVKs   int
	HESyncPeakMem    float64 // MB
	HESyncStallTime  time.Duration
	DryRunLatency    time.Duration
	TraceLength      int
	EVKSizeMB        float64 // Size of a single EVK in MB
}

// Overhead returns the HESync execution time overhead as a percentage.
func (r BenchmarkResult) Overhead() float64 {
	if r.BaselineLatency == 0 {
		return 0
	}
	return float64(r.HESyncLatency-r.BaselineLatency) / float64(r.BaselineLatency) * 100
}

// EVKReduction returns the percentage reduction in peak EVKs.
func (r BenchmarkResult) EVKReduction() float64 {
	if r.BaselinePeakEVKs == 0 {
		return 0
	}
	return (1 - float64(r.HESyncPeakEVKs)/float64(r.BaselinePeakEVKs)) * 100
}

// StallPercent returns stall time as a percentage of HESync latency.
func (r BenchmarkResult) StallPercent() float64 {
	if r.HESyncLatency == 0 {
		return 0
	}
	return float64(r.HESyncStallTime) / float64(r.HESyncLatency) * 100
}

// RunBenchmark executes the full HESync benchmark pipeline for a given workload.
func RunBenchmark(cfg BenchmarkConfig, workload Workload, ct *ckks.Ciphertext) ([]BenchmarkResult, error) {
	if cfg.ProfileIters <= 0 {
		cfg.ProfileIters = 3
	}

	// Step 1: Baseline run
	baselineEval := ckks.NewEvaluator(cfg.Params, cfg.EvalKey)
	totalEVKs := countEVKs(cfg.EvalKey)

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	baselineStart := time.Now()
	workload(baselineEval, ct)
	baselineLatency := time.Since(baselineStart)

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	baselinePeakMem := float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / (1024 * 1024)

	// Step 2: Save EVKs to disk
	store, err := NewEVKStore(cfg.EVKStoreDir)
	if err != nil {
		return nil, fmt.Errorf("benchmark: create evk store: %w", err)
	}
	if err := store.SaveAll(cfg.EvalKey.Rlk, cfg.EvalKey.Rtks); err != nil {
		return nil, fmt.Errorf("benchmark: save evks: %w", err)
	}
	evkSizeMB := float64(store.KeySize()) / (1024 * 1024)

	// Step 3: Dry run (trace)
	dryRunStart := time.Now()
	tracer := NewTracingEvaluator(cfg.Params)
	tracerCt := newTracerCiphertext(cfg.Params, ct.Degree(), ct.Level(), ct.Scale)
	workload(tracer, tracerCt)
	trace := tracer.GetTrace()

	// Step 4: Profile
	profiler := NewProfiler(cfg.Params)
	profiler.SetIterations(cfg.ProfileIters)
	profile := profiler.ProfileFromTrace(trace, cfg.EvalKey, store)
	dryRunLatency := time.Since(dryRunStart)

	// Step 5: Run for each criterion
	var results []BenchmarkResult
	for _, criterion := range cfg.Criteria {
		plan := GeneratePlan(trace, profile, criterion)

		// Set up HESync runtime
		container := NewEVKContainer()
		innerEval := ckks.NewEvaluator(cfg.Params, rlwe.EvaluationKey{
			Rlk:  container.RelinearizationKey(),
			Rtks: container.RotationKeySet(),
		})

		// Pre-compute NTT indexes for all rotation keys
		if cfg.EvalKey.Rtks != nil {
			galEls := make([]uint64, 0, len(cfg.EvalKey.Rtks.Keys))
			for galEl := range cfg.EvalKey.Rtks.Keys {
				galEls = append(galEls, galEl)
			}
			innerEval.PreparePermuteNTTIndex(galEls)
		}

		prefetcher := NewPrefetcher(plan, store, container)
		hesyncEval := NewHESyncEvaluator(innerEval, prefetcher)

		runtime.GC()
		runtime.ReadMemStats(&memBefore)

		hesyncStart := time.Now()
		workload(hesyncEval, ct)
		hesyncLatency := time.Since(hesyncStart)

		runtime.ReadMemStats(&memAfter)
		hesyncPeakMem := float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / (1024 * 1024)

		results = append(results, BenchmarkResult{
			Criterion:        criterion,
			BaselineLatency:  baselineLatency,
			BaselinePeakEVKs: totalEVKs,
			BaselinePeakMem:  baselinePeakMem,
			HESyncLatency:    hesyncLatency,
			HESyncPeakEVKs:   container.PeakCount(),
			HESyncPeakMem:    hesyncPeakMem,
			HESyncStallTime:  prefetcher.StallTime(),
			DryRunLatency:    dryRunLatency,
			TraceLength:      len(trace.Entries),
			EVKSizeMB:        evkSizeMB,
		})

		container.Reset()
	}

	return results, nil
}

// WriteResults writes benchmark results to a writer in tabular text format.
func WriteResults(w io.Writer, results []BenchmarkResult) {
	fmt.Fprintf(w, "HESync Benchmark Results\n")
	fmt.Fprintf(w, "========================\n\n")

	if len(results) == 0 {
		fmt.Fprintf(w, "No results.\n")
		return
	}

	r0 := results[0]
	fmt.Fprintf(w, "Trace length:       %d operations\n", r0.TraceLength)
	fmt.Fprintf(w, "Baseline latency:   %v\n", r0.BaselineLatency)
	fmt.Fprintf(w, "Baseline peak EVKs: %d\n", r0.BaselinePeakEVKs)
	fmt.Fprintf(w, "EVK size:           %.2f MB\n", r0.EVKSizeMB)
	fmt.Fprintf(w, "Baseline peak mem:  %.2f MB (EVK only: %.2f MB)\n",
		r0.BaselinePeakMem,
		float64(r0.BaselinePeakEVKs)*r0.EVKSizeMB)
	fmt.Fprintf(w, "Dry run latency:    %v\n\n", r0.DryRunLatency)

	// Table header
	fmt.Fprintf(w, "%-12s %12s %10s %10s %10s %10s %10s\n",
		"Criterion", "Latency", "Overhead%", "PeakEVKs", "Reduction%", "Stall", "Stall%")
	fmt.Fprintf(w, "%-12s %12s %10s %10s %10s %10s %10s\n",
		"----------", "----------", "--------", "--------", "----------", "--------", "------")

	for _, r := range results {
		fmt.Fprintf(w, "%-12s %12v %9.1f%% %10d %9.1f%% %10v %9.1f%%\n",
			r.Criterion,
			r.HESyncLatency.Round(time.Millisecond),
			r.Overhead(),
			r.HESyncPeakEVKs,
			r.EVKReduction(),
			r.HESyncStallTime.Round(time.Millisecond),
			r.StallPercent())
	}

	fmt.Fprintf(w, "\n")
}

func countEVKs(evk rlwe.EvaluationKey) int {
	count := 0
	if evk.Rlk != nil {
		for _, k := range evk.Rlk.Keys {
			if k != nil {
				count++
			}
		}
	}
	if evk.Rtks != nil {
		for _, k := range evk.Rtks.Keys {
			if k != nil {
				count++
			}
		}
	}
	return count
}
