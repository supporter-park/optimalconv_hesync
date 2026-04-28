package hesync

import (
	"time"

	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/supporter-park/optimalconv_hesync/utils"
)

// Profile stores level-aware timing measurements for HE operations.
type Profile struct {
	// OpTimings maps OpType -> level -> average duration.
	OpTimings map[string]map[int]time.Duration

	// EVKLoadTime is the average time to load a single EVK from disk.
	EVKLoadTime time.Duration

	// BootstrapTime is the measured time for a full bootstrap operation.
	// Zero if not profiled.
	BootstrapTime time.Duration

	// MaxLevel is the maximum ciphertext level in the scheme.
	MaxLevel int
}

// GetDuration returns the profiled duration for an operation based on the plan criterion.
func (p *Profile) GetDuration(entry TraceEntry, criterion PlanCriterion) time.Duration {
	if entry.OpType == "Bootstrap" {
		return p.BootstrapTime
	}

	timings, ok := p.OpTimings[entry.OpType]
	if !ok {
		return 0
	}

	var level int
	switch criterion {
	case CriterionLevel0:
		level = 0
	case CriterionHalfMax:
		level = p.MaxLevel / 2
	case CriterionMaxLevel:
		level = p.MaxLevel
	case CriterionPerTrace:
		level = entry.InputLevel
	case CriterionLazyLoad:
		// LazyLoad does not use profiled durations for planning;
		// return 0 so the planner's reverse-walk is never reached.
		return 0
	}

	if d, ok := timings[level]; ok {
		return d
	}

	// Fallback: find the closest available level
	return p.closestLevelTiming(timings, level)
}

func (p *Profile) closestLevelTiming(timings map[int]time.Duration, target int) time.Duration {
	bestDist := -1
	var bestDur time.Duration
	for lvl, dur := range timings {
		dist := target - lvl
		if dist < 0 {
			dist = -dist
		}
		if bestDist < 0 || dist < bestDist {
			bestDist = dist
			bestDur = dur
		}
	}
	return bestDur
}

// Profiler measures HE operation latencies at various ciphertext levels.
type Profiler struct {
	params ckks.Parameters
	// iterations is the number of times each operation is timed for averaging.
	iterations int
	// evk is set during ProfileFromTrace so opFunc can pick a galois element
	// that actually exists in the evaluator's rotation key set.
	evk rlwe.EvaluationKey
}

// NewProfiler creates a new Profiler.
func NewProfiler(params ckks.Parameters) *Profiler {
	return &Profiler{
		params:     params,
		iterations: 3,
	}
}

// SetIterations sets the number of timing iterations per operation (default 3).
func (pr *Profiler) SetIterations(n int) {
	if n > 0 {
		pr.iterations = n
	}
}

// anyAvailableGalEl returns a non-row galois element present in the current
// evk's rotation key set, preferring the smallest positive k. Returns 0 if
// there is no usable rotation key (caller must treat 0 as "skip this op").
func (pr *Profiler) anyAvailableGalEl() uint64 {
	if pr.evk.Rtks == nil || len(pr.evk.Rtks.Keys) == 0 {
		return 0
	}
	rowGal := pr.params.GaloisElementForRowRotation()
	// Prefer a column rotation (not the row/conjugation one) for consistent
	// profiling behavior.
	var fallback uint64
	for galEl := range pr.evk.Rtks.Keys {
		if galEl == rowGal {
			continue
		}
		if fallback == 0 || galEl < fallback {
			fallback = galEl
		}
	}
	if fallback != 0 {
		return fallback
	}
	// Only the row-rotation key is present — better than nothing.
	return rowGal
}

// ProfileFromTrace profiles all operations that appear in the trace.
// It creates a real evaluator with the given keys and times each (OpType, Level) pair.
// If evkStore is non-nil, it also measures EVK load latency.
func (pr *Profiler) ProfileFromTrace(trace *Trace, evk rlwe.EvaluationKey, evkStore *EVKStore) *Profile {
	profile := &Profile{
		OpTimings: make(map[string]map[int]time.Duration),
		MaxLevel:  pr.params.MaxLevel(),
	}

	// Discover unique (OpType, Level) pairs from the trace
	type opLevelKey struct {
		opType string
		level  int
	}
	needed := make(map[opLevelKey]bool)
	for _, entry := range trace.Entries {
		if entry.OpType == "Bootstrap" {
			continue // bootstrap is profiled separately
		}
		needed[opLevelKey{entry.OpType, entry.InputLevel}] = true
	}

	// Create a real evaluator for profiling
	eval := ckks.NewEvaluator(pr.params, evk)
	pr.evk = evk

	// Profile each (OpType, Level) pair
	for key := range needed {
		dur := pr.profileOp(eval, key.opType, key.level)
		if _, ok := profile.OpTimings[key.opType]; !ok {
			profile.OpTimings[key.opType] = make(map[int]time.Duration)
		}
		profile.OpTimings[key.opType][key.level] = dur
	}

	// Measure EVK load latency
	if evkStore != nil {
		profile.EVKLoadTime = evkStore.LoadLatency()
	}

	return profile
}

// SetBootstrapTime sets the bootstrap profiling result.
// This is separate because bootstrap requires a full Bootstrapper setup
// and the caller manages its lifecycle.
func (p *Profile) SetBootstrapTime(d time.Duration) {
	p.BootstrapTime = d
}

// profileOp runs a single operation at the given level and returns the average duration.
func (pr *Profiler) profileOp(eval ckks.Evaluator, opType string, level int) time.Duration {
	if level < 0 {
		level = 0
	}
	if level > pr.params.MaxLevel() {
		level = pr.params.MaxLevel()
	}

	// Generate test ciphertexts at the target level
	prng, err := utils.NewPRNG()
	if err != nil {
		return 0
	}

	ct0 := ckks.NewCiphertextRandom(prng, pr.params, 1, level, pr.params.Scale())
	ct1 := ckks.NewCiphertextRandom(prng, pr.params, 1, level, pr.params.Scale())
	ctOut := ckks.NewCiphertext(pr.params, 1, level, pr.params.Scale())

	fn := pr.opFunc(eval, opType, ct0, ct1, ctOut, level)
	if fn == nil {
		return 0
	}

	// Warm-up run
	fn()

	// Timed runs
	var total time.Duration
	for i := 0; i < pr.iterations; i++ {
		// Re-create ciphertexts to avoid state accumulation
		ct0 = ckks.NewCiphertextRandom(prng, pr.params, 1, level, pr.params.Scale())
		ct1 = ckks.NewCiphertextRandom(prng, pr.params, 1, level, pr.params.Scale())
		ctOut = ckks.NewCiphertext(pr.params, 1, level, pr.params.Scale())
		fn = pr.opFunc(eval, opType, ct0, ct1, ctOut, level)

		start := time.Now()
		fn()
		total += time.Since(start)
	}

	return total / time.Duration(pr.iterations)
}

// opFunc returns a closure that runs the specified operation once.
// Returns nil if the operation is not recognized or cannot be profiled at the given level.
func (pr *Profiler) opFunc(eval ckks.Evaluator, opType string, ct0, ct1, ctOut *ckks.Ciphertext, level int) func() {
	switch opType {
	case "Add":
		return func() { eval.Add(ct0, ct1, ctOut) }
	case "Sub":
		return func() { eval.Sub(ct0, ct1, ctOut) }
	case "Neg":
		return func() { eval.Neg(ct0, ctOut) }
	case "AddConst":
		return func() { eval.AddConst(ct0, 3.14, ctOut) }
	case "MultByConst":
		return func() { eval.MultByConst(ct0, 3.14, ctOut) }
	case "MultByGaussianInteger":
		return func() { eval.MultByGaussianInteger(ct0, 1, 1, ctOut) }
	case "MultByConstAndAdd":
		return func() { eval.MultByConstAndAdd(ct0, 3.14, ctOut) }
	case "MultByGaussianIntegerAndAdd":
		return func() { eval.MultByGaussianIntegerAndAdd(ct0, 1, 1, ctOut) }
	case "MultByi":
		return func() { eval.MultByi(ct0, ctOut) }
	case "DivByi":
		return func() { eval.DivByi(ct0, ctOut) }
	case "Mul":
		ctOut2 := ckks.NewCiphertext(pr.params, 2, level, pr.params.Scale())
		return func() { eval.Mul(ct0, ct1, ctOut2) }
	case "MulRelin":
		return func() { eval.MulRelin(ct0, ct1, ctOut) }
	case "Relinearize":
		ct2 := ckks.NewCiphertext(pr.params, 2, level, pr.params.Scale())
		// Fill ct2 with data from a Mul
		eval.Mul(ct0, ct1, ct2)
		return func() { eval.Relinearize(ct2, ctOut) }
	case "Rotate":
		galEl := pr.anyAvailableGalEl()
		if galEl == 0 {
			return nil
		}
		return func() { eval.RotateGal(ct0, galEl, ctOut) }
	case "RotateGal":
		galEl := pr.anyAvailableGalEl()
		if galEl == 0 {
			return nil
		}
		return func() { eval.RotateGal(ct0, galEl, ctOut) }
	case "Conjugate":
		// Conjugate needs the row-rotation galois element.
		if pr.evk.Rtks == nil {
			return nil
		}
		rowGal := pr.params.GaloisElementForRowRotation()
		if _, ok := pr.evk.Rtks.Keys[rowGal]; !ok {
			return nil
		}
		return func() { eval.Conjugate(ct0, ctOut) }
	case "RotateHoisted":
		galEl := pr.anyAvailableGalEl()
		if galEl == 0 {
			return nil
		}
		k := int(pr.params.InverseGaloisElement(galEl))
		return func() { eval.RotateHoisted(ct0, []int{k}) }
	case "Rescale":
		if level == 0 {
			return nil // Cannot rescale at level 0
		}
		// Create a ciphertext with squared scale to ensure rescale happens
		ct := ckks.NewCiphertext(pr.params, 1, level, ct0.Scale*ct0.Scale)
		copy(ct.Value[0].Coeffs[0], ct0.Value[0].Coeffs[0])
		copy(ct.Value[1].Coeffs[0], ct0.Value[1].Coeffs[0])
		return func() {
			ctR := ckks.NewCiphertext(pr.params, 1, level, 0)
			eval.Rescale(ct, pr.params.Scale()/2, ctR)
		}
	case "DropLevel":
		if level == 0 {
			return nil
		}
		return func() {
			ct := ckks.NewCiphertext(pr.params, 1, level, pr.params.Scale())
			eval.DropLevel(ct, 1)
		}
	case "ScaleUp":
		return func() { eval.ScaleUp(ct0, 2.0, ctOut) }
	case "MulByPow2":
		return func() { eval.MulByPow2(ct0, 1, ctOut) }
	case "Reduce":
		return func() { eval.Reduce(ct0, ctOut) }
	case "SwitchKeys":
		// SwitchKeys requires an explicit key; skip if not available
		return nil
	case "LinearTransform", "MultiplyByDiagMatrix", "MultiplyByDiagMatrixBSGS":
		// LinearTransform requires pre-encoded matrices; skip in generic profiling.
		// It is composed of rotations + multiplications, so those are profiled individually.
		return nil
	case "InnerSumLog", "InnerSum":
		return func() { eval.InnerSumLog(ct0, 1, 2, ctOut) }
	case "EvaluatePoly", "EvaluateCheby":
		// These are composed of MulRelin + Rescale; the component ops are profiled.
		return nil
	case "Inverse":
		return nil // Composed of basic operations
	default:
		return nil
	}
}
