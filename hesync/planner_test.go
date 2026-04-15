package hesync

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// syntheticProfile creates a Profile with fixed durations for testing.
func syntheticProfile(opDuration, evkLoadTime time.Duration, maxLevel int) *Profile {
	return &Profile{
		OpTimings: map[string]map[int]time.Duration{
			"Add":      {0: opDuration, 1: opDuration, 2: opDuration, 3: opDuration},
			"MulRelin": {0: opDuration, 1: opDuration, 2: opDuration, 3: opDuration},
			"Rotate":   {0: opDuration, 1: opDuration, 2: opDuration, 3: opDuration},
			"Rescale":  {0: opDuration, 1: opDuration, 2: opDuration, 3: opDuration},
		},
		EVKLoadTime:   evkLoadTime,
		BootstrapTime: 100 * time.Millisecond,
		MaxLevel:      maxLevel,
	}
}

func TestPlannerSingleEVKOp(t *testing.T) {
	// Trace: [Add, Add, Rotate]
	// Rotate at index 2 needs a rotation key.
	// With each op taking 10ms and EVK load taking 15ms,
	// the fetch should be placed 2 ops before (15ms / 10ms = 1.5 ops back => index 0 or 1).

	rotEVK := EVKIdentifier{Type: RotationKey, GaloisEl: 5}
	trace := &Trace{
		Entries: []TraceEntry{
			{OpIndex: 0, OpType: "Add", InputLevel: 3, OutputLevel: 3},
			{OpIndex: 1, OpType: "Add", InputLevel: 3, OutputLevel: 3},
			{OpIndex: 2, OpType: "Rotate", InputLevel: 3, OutputLevel: 3, EVKs: []EVKIdentifier{rotEVK}},
		},
		MaxLevel: 5,
	}

	profile := syntheticProfile(10*time.Millisecond, 15*time.Millisecond, 5)

	plan := GeneratePlan(trace, profile, CriterionPerTrace)

	require.Equal(t, 3, len(plan.Instructions))

	// Index 2: must have Sync for the rotation key
	require.True(t, plan.Instructions[2].HasSync())
	require.Equal(t, []EVKIdentifier{rotEVK}, plan.Instructions[2].SyncEVKs)

	// The fetch countdown starts at index 2 with 15ms.
	// Walking back: index 2 subtracts 10ms (Rotate) -> 5ms remaining
	//               index 1 subtracts 10ms (Add) -> -5ms <= 0, Fetch placed at index 1
	require.True(t, plan.Instructions[1].HasFetch(),
		"Fetch should be at index 1 (timer expires after subtracting index 1's duration)")
	require.Equal(t, []EVKIdentifier{rotEVK}, plan.Instructions[1].FetchEVKs)

	// Index 0: Nop
	require.True(t, plan.Instructions[0].IsNop())
}

func TestPlannerFetchAtZeroWhenNotEnoughTime(t *testing.T) {
	// Trace: [Rotate] — single operation needing EVK, no prior ops to absorb load time.
	// Fetch must be placed at index 0 (same position as sync), causing a stall.

	rotEVK := EVKIdentifier{Type: RotationKey, GaloisEl: 5}
	trace := &Trace{
		Entries: []TraceEntry{
			{OpIndex: 0, OpType: "Rotate", InputLevel: 3, OutputLevel: 3, EVKs: []EVKIdentifier{rotEVK}},
		},
		MaxLevel: 5,
	}

	profile := syntheticProfile(10*time.Millisecond, 50*time.Millisecond, 5)

	plan := GeneratePlan(trace, profile, CriterionPerTrace)

	require.Equal(t, 1, len(plan.Instructions))
	// Both fetch and sync at index 0
	require.True(t, plan.Instructions[0].HasFetch())
	require.True(t, plan.Instructions[0].HasSync())
}

func TestPlannerNoEVKOps(t *testing.T) {
	// Trace: [Add, Sub, Neg] — no EVK operations, all Nop.
	trace := &Trace{
		Entries: []TraceEntry{
			{OpIndex: 0, OpType: "Add", InputLevel: 3, OutputLevel: 3},
			{OpIndex: 1, OpType: "Sub", InputLevel: 3, OutputLevel: 3},
			{OpIndex: 2, OpType: "Neg", InputLevel: 3, OutputLevel: 3},
		},
		MaxLevel: 5,
	}

	profile := syntheticProfile(10*time.Millisecond, 15*time.Millisecond, 5)
	plan := GeneratePlan(trace, profile, CriterionPerTrace)

	for i, inst := range plan.Instructions {
		require.True(t, inst.IsNop(), "instruction %d should be Nop", i)
	}
}

func TestPlannerMultipleEVKOps(t *testing.T) {
	// Trace: [Add, MulRelin, Add, Add, Rotate]
	// MulRelin at 1 needs relin key, Rotate at 4 needs rot key.
	// Each op = 10ms, EVK load = 25ms.
	//
	// For Rotate@4: timer=25ms, walk back:
	//   4: -10ms=15ms, 3: -10ms=5ms, 2: -10ms=-5ms => Fetch at 2
	// For MulRelin@1: timer=25ms, walk back:
	//   1: -10ms=15ms, 0: -10ms=5ms => still pending at start => Fetch at 0

	relinEVK := EVKIdentifier{Type: RelinKey, GaloisEl: 0}
	rotEVK := EVKIdentifier{Type: RotationKey, GaloisEl: 7}

	trace := &Trace{
		Entries: []TraceEntry{
			{OpIndex: 0, OpType: "Add", InputLevel: 3, OutputLevel: 3},
			{OpIndex: 1, OpType: "MulRelin", InputLevel: 3, OutputLevel: 3, EVKs: []EVKIdentifier{relinEVK}},
			{OpIndex: 2, OpType: "Add", InputLevel: 3, OutputLevel: 3},
			{OpIndex: 3, OpType: "Add", InputLevel: 3, OutputLevel: 3},
			{OpIndex: 4, OpType: "Rotate", InputLevel: 3, OutputLevel: 3, EVKs: []EVKIdentifier{rotEVK}},
		},
		MaxLevel: 5,
	}

	profile := syntheticProfile(10*time.Millisecond, 25*time.Millisecond, 5)
	plan := GeneratePlan(trace, profile, CriterionPerTrace)

	// Index 0: Fetch for MulRelin (timer didn't expire in time, falls to index 0)
	require.True(t, plan.Instructions[0].HasFetch())
	require.Contains(t, plan.Instructions[0].FetchEVKs, relinEVK)

	// Index 1: Sync for MulRelin
	require.True(t, plan.Instructions[1].HasSync())
	require.Contains(t, plan.Instructions[1].SyncEVKs, relinEVK)

	// Index 2: Fetch for Rotate
	require.True(t, plan.Instructions[2].HasFetch())
	require.Contains(t, plan.Instructions[2].FetchEVKs, rotEVK)

	// Index 4: Sync for Rotate
	require.True(t, plan.Instructions[4].HasSync())
	require.Contains(t, plan.Instructions[4].SyncEVKs, rotEVK)
}

func TestPlannerCriterionAffectsFetchPlacement(t *testing.T) {
	// A trace with ops at different levels. Criterion selection affects how much
	// compute time each op is estimated to take, thus changing Fetch placement.

	rotEVK := EVKIdentifier{Type: RotationKey, GaloisEl: 5}
	trace := &Trace{
		Entries: []TraceEntry{
			{OpIndex: 0, OpType: "Add", InputLevel: 0, OutputLevel: 0},
			{OpIndex: 1, OpType: "Add", InputLevel: 0, OutputLevel: 0},
			{OpIndex: 2, OpType: "Add", InputLevel: 0, OutputLevel: 0},
			{OpIndex: 3, OpType: "Add", InputLevel: 0, OutputLevel: 0},
			{OpIndex: 4, OpType: "Rotate", InputLevel: 0, OutputLevel: 0, EVKs: []EVKIdentifier{rotEVK}},
		},
		MaxLevel: 4,
	}

	// Profile where level 0 is fast (5ms) and level 4 is slow (30ms)
	profile := &Profile{
		OpTimings: map[string]map[int]time.Duration{
			"Add":    {0: 5 * time.Millisecond, 2: 15 * time.Millisecond, 4: 30 * time.Millisecond},
			"Rotate": {0: 5 * time.Millisecond, 2: 15 * time.Millisecond, 4: 30 * time.Millisecond},
		},
		EVKLoadTime: 20 * time.Millisecond,
		MaxLevel:    4,
	}

	// CriterionPerTrace: ops at level 0 (5ms each).
	// Timer=20ms, walk back: 4:-5=15, 3:-5=10, 2:-5=5, 1:-5=0 => Fetch at 1
	planPT := GeneratePlan(trace, profile, CriterionPerTrace)
	require.True(t, planPT.Instructions[1].HasFetch(),
		"PerTrace: Fetch should be at index 1")

	// CriterionMaxLevel: ops estimated at level 4 (30ms each).
	// Timer=20ms, walk back: 4:-30=-10 => Fetch at 4 itself
	planML := GeneratePlan(trace, profile, CriterionMaxLevel)
	require.True(t, planML.Instructions[4].HasFetch(),
		"MaxLevel: Fetch should be at index 4 (timer expires immediately with 30ms ops)")
}

func TestPlannerLastUseMap(t *testing.T) {
	relinEVK := EVKIdentifier{Type: RelinKey, GaloisEl: 0}
	rotEVK := EVKIdentifier{Type: RotationKey, GaloisEl: 5}

	trace := &Trace{
		Entries: []TraceEntry{
			{OpIndex: 0, OpType: "MulRelin", InputLevel: 3, EVKs: []EVKIdentifier{relinEVK}},
			{OpIndex: 1, OpType: "Rotate", InputLevel: 3, EVKs: []EVKIdentifier{rotEVK}},
			{OpIndex: 2, OpType: "MulRelin", InputLevel: 3, EVKs: []EVKIdentifier{relinEVK}},
			{OpIndex: 3, OpType: "Add", InputLevel: 3},
		},
	}

	profile := syntheticProfile(10*time.Millisecond, 5*time.Millisecond, 5)
	plan := GeneratePlan(trace, profile, CriterionPerTrace)

	lastUse := plan.LastUseMap()

	// Relin key last used at index 2
	require.Equal(t, 2, lastUse[relinEVK])
	// Rotation key last used at index 1
	require.Equal(t, 1, lastUse[rotEVK])
}

func TestPlannerStats(t *testing.T) {
	rotEVK := EVKIdentifier{Type: RotationKey, GaloisEl: 5}
	trace := &Trace{
		Entries: []TraceEntry{
			{OpIndex: 0, OpType: "Add", InputLevel: 3},
			{OpIndex: 1, OpType: "Add", InputLevel: 3},
			{OpIndex: 2, OpType: "Rotate", InputLevel: 3, EVKs: []EVKIdentifier{rotEVK}},
		},
		MaxLevel: 5,
	}

	profile := syntheticProfile(10*time.Millisecond, 15*time.Millisecond, 5)
	plan := GeneratePlan(trace, profile, CriterionPerTrace)

	stats := plan.Stats()
	require.Equal(t, 3, stats.TotalOps)
	require.Equal(t, 1, stats.SyncCount)  // Only index 2 has Sync
	require.Equal(t, 1, stats.FetchCount) // Fetch at index 1
}

func TestPlannerBootstrapConsumesDuration(t *testing.T) {
	// Bootstrap should consume BootstrapTime worth of countdown.
	// Trace: [Bootstrap, Rotate]
	// Bootstrap takes 100ms (from profile), EVK load = 50ms.
	// For Rotate@1: timer=50ms, walk back:
	//   1: -10ms(Rotate)=40ms, 0: -100ms(Bootstrap)=-60ms => Fetch at 0

	rotEVK := EVKIdentifier{Type: RotationKey, GaloisEl: 5}
	trace := &Trace{
		Entries: []TraceEntry{
			{OpIndex: 0, OpType: "Bootstrap", InputLevel: 0, OutputLevel: 10},
			{OpIndex: 1, OpType: "Rotate", InputLevel: 3, OutputLevel: 3, EVKs: []EVKIdentifier{rotEVK}},
		},
		MaxLevel: 10,
	}

	profile := &Profile{
		OpTimings: map[string]map[int]time.Duration{
			"Rotate": {3: 10 * time.Millisecond},
		},
		EVKLoadTime:   50 * time.Millisecond,
		BootstrapTime: 100 * time.Millisecond,
		MaxLevel:      10,
	}

	plan := GeneratePlan(trace, profile, CriterionPerTrace)

	// Fetch at index 0 (Bootstrap absorbs the countdown)
	require.True(t, plan.Instructions[0].HasFetch())
	require.Contains(t, plan.Instructions[0].FetchEVKs, rotEVK)

	// Sync at index 1
	require.True(t, plan.Instructions[1].HasSync())
}

func TestPlannerConsecutiveEVKOps(t *testing.T) {
	// Two consecutive EVK operations: [MulRelin, Rotate]
	// Each needs its own Fetch+Sync pair.

	relinEVK := EVKIdentifier{Type: RelinKey, GaloisEl: 0}
	rotEVK := EVKIdentifier{Type: RotationKey, GaloisEl: 5}

	trace := &Trace{
		Entries: []TraceEntry{
			{OpIndex: 0, OpType: "MulRelin", InputLevel: 3, OutputLevel: 3, EVKs: []EVKIdentifier{relinEVK}},
			{OpIndex: 1, OpType: "Rotate", InputLevel: 3, OutputLevel: 3, EVKs: []EVKIdentifier{rotEVK}},
		},
		MaxLevel: 5,
	}

	profile := syntheticProfile(10*time.Millisecond, 5*time.Millisecond, 5)
	plan := GeneratePlan(trace, profile, CriterionPerTrace)

	// Both ops have Sync
	require.True(t, plan.Instructions[0].HasSync())
	require.True(t, plan.Instructions[1].HasSync())

	// Fetches: since EVK load (5ms) < op duration (10ms), both fetches should
	// land at the op positions themselves.
	// For Rotate@1: timer=5ms, walk back: 1:-10ms=-5ms => Fetch at 1
	// For MulRelin@0: timer=5ms, walk back: 0:-10ms=-5ms => Fetch at 0
	require.True(t, plan.Instructions[0].HasFetch())
	require.True(t, plan.Instructions[1].HasFetch())
}
