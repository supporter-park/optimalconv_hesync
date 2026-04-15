package hesync

import (
	"time"
)

// PlanInstruction is the prefetch instruction for a single trace entry position.
// A position may have both a Fetch (start loading EVKs for a future operation)
// and a Sync (wait for EVKs needed by the current operation).
type PlanInstruction struct {
	// FetchEVKs are the EVKs to begin loading at this position (for a future Sync).
	FetchEVKs []EVKIdentifier

	// SyncEVKs are the EVKs that must be available before this operation executes.
	SyncEVKs []EVKIdentifier
}

// HasFetch returns true if this instruction triggers an EVK load.
func (pi PlanInstruction) HasFetch() bool {
	return len(pi.FetchEVKs) > 0
}

// HasSync returns true if this instruction requires waiting for loaded EVKs.
func (pi PlanInstruction) HasSync() bool {
	return len(pi.SyncEVKs) > 0
}

// IsNop returns true if this instruction has no prefetch activity.
func (pi PlanInstruction) IsNop() bool {
	return !pi.HasFetch() && !pi.HasSync()
}

// Plan is the output of the Planner: a sequence of prefetch instructions
// parallel-indexed with the Trace entries.
type Plan struct {
	Instructions []PlanInstruction
	Trace        *Trace
	Criterion    PlanCriterion
}

// LastUseMap computes for each EVK the last trace index at which it is needed.
// This is used by the Prefetcher to free EVKs immediately after their last use.
func (p *Plan) LastUseMap() map[EVKIdentifier]int {
	lastUse := make(map[EVKIdentifier]int)
	for i, entry := range p.Trace.Entries {
		for _, evk := range entry.EVKs {
			lastUse[evk] = i
		}
	}
	return lastUse
}

// Stats returns summary statistics about the plan.
type PlanStats struct {
	TotalOps   int
	FetchCount int
	SyncCount  int
	NopCount   int
}

func (p *Plan) Stats() PlanStats {
	stats := PlanStats{TotalOps: len(p.Instructions)}
	for _, inst := range p.Instructions {
		if inst.HasFetch() {
			stats.FetchCount++
		}
		if inst.HasSync() {
			stats.SyncCount++
		}
		if inst.IsNop() {
			stats.NopCount++
		}
	}
	return stats
}

// pendingFetch tracks a fetch that needs to be placed during the reverse walk.
type pendingFetch struct {
	evkIDs    []EVKIdentifier
	remaining time.Duration // countdown timer: how much more compute time we need to walk past
}

// GeneratePlan creates a prefetch plan from a trace and profile using the
// reverse-walk algorithm described in the HESync paper.
//
// Algorithm:
//  1. Walk the trace in reverse (last entry to first).
//  2. When an entry uses EVKs, record a Sync at that position and start a
//     countdown timer set to profile.EVKLoadTime.
//  3. Continue walking backward, subtracting each entry's profiled duration
//     from active countdown timers.
//  4. When a timer reaches zero, place a Fetch at that position.
//  5. If a timer hasn't reached zero by the start of the trace, place the
//     Fetch at index 0 (this will cause a stall at runtime).
//  6. All other positions get Nop (empty instruction).
func GeneratePlan(trace *Trace, profile *Profile, criterion PlanCriterion) *Plan {
	n := len(trace.Entries)
	instructions := make([]PlanInstruction, n)

	// Active pending fetches: timers counting down as we walk backward.
	var pending []*pendingFetch

	// Reverse walk
	for i := n - 1; i >= 0; i-- {
		entry := trace.Entries[i]

		// Step 1: If this entry uses EVKs, record a Sync and start a countdown.
		if len(entry.EVKs) > 0 {
			instructions[i].SyncEVKs = append(instructions[i].SyncEVKs, entry.EVKs...)
			pending = append(pending, &pendingFetch{
				evkIDs:    entry.EVKs,
				remaining: profile.EVKLoadTime,
			})
		}

		// Step 2: Subtract this entry's profiled duration from all active timers.
		opDuration := profile.GetDuration(entry, criterion)
		var stillPending []*pendingFetch
		for _, pf := range pending {
			pf.remaining -= opDuration

			if pf.remaining <= 0 {
				// Timer expired: place Fetch at this position
				instructions[i].FetchEVKs = append(instructions[i].FetchEVKs, pf.evkIDs...)
			} else {
				stillPending = append(stillPending, pf)
			}
		}
		pending = stillPending
	}

	// Step 3: Any timers that haven't expired get placed at index 0 (will stall).
	for _, pf := range pending {
		instructions[0].FetchEVKs = append(instructions[0].FetchEVKs, pf.evkIDs...)
	}

	return &Plan{
		Instructions: instructions,
		Trace:        trace,
		Criterion:    criterion,
	}
}
