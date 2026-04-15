package hesync

import (
	"sync"
	"time"
)

// loadTask represents an in-flight EVK load from disk.
type loadTask struct {
	id   EVKIdentifier
	done chan struct{}
	err  error
}

// Prefetcher executes a Plan by asynchronously loading EVKs from disk
// ahead of when they are needed by the evaluator.
type Prefetcher struct {
	plan      *Plan
	evkStore  *EVKStore
	container *EVKContainer
	lastUse   map[EVKIdentifier]int // EVK ID -> last trace index that uses it

	mu        sync.Mutex
	pending   []*loadTask    // queue of in-flight loads
	stallTime time.Duration  // accumulated stall time
}

// NewPrefetcher creates a Prefetcher for the given plan.
func NewPrefetcher(plan *Plan, store *EVKStore, container *EVKContainer) *Prefetcher {
	return &Prefetcher{
		plan:      plan,
		evkStore:  store,
		container: container,
		lastUse:   plan.LastUseMap(),
	}
}

// HandleInstruction processes the plan instruction for the given operation index.
// This is called by the HESyncEvaluator before each operation.
//
// For Fetch instructions: launches async loads for the requested EVKs.
// For Sync instructions: blocks until all pending loads for the sync EVKs complete.
func (pf *Prefetcher) HandleInstruction(opIndex int) {
	if opIndex >= len(pf.plan.Instructions) {
		return
	}
	inst := pf.plan.Instructions[opIndex]

	// Process Fetch: launch async loads
	if inst.HasFetch() {
		pf.startLoads(inst.FetchEVKs)
	}

	// Process Sync: wait for required EVKs
	if inst.HasSync() {
		pf.waitForEVKs(inst.SyncEVKs)
	}
}

// FreeUnneeded removes EVKs from the container whose last use is at or before opIndex.
func (pf *Prefetcher) FreeUnneeded(opIndex int) {
	for id, lastIdx := range pf.lastUse {
		if lastIdx <= opIndex {
			pf.container.Remove(id)
		}
	}
}

// StallTime returns the total time spent waiting for EVKs that weren't ready.
func (pf *Prefetcher) StallTime() time.Duration {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	return pf.stallTime
}

// startLoads launches goroutines to load EVKs from disk.
func (pf *Prefetcher) startLoads(evkIDs []EVKIdentifier) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	for _, id := range evkIDs {
		// Skip if already loaded
		if pf.container.Has(id) {
			continue
		}

		// Skip if already being loaded
		alreadyPending := false
		for _, t := range pf.pending {
			if t.id == id {
				alreadyPending = true
				break
			}
		}
		if alreadyPending {
			continue
		}

		task := &loadTask{
			id:   id,
			done: make(chan struct{}),
		}
		pf.pending = append(pf.pending, task)

		go func(t *loadTask) {
			key, err := pf.evkStore.Load(t.id)
			if err != nil {
				t.err = err
			} else {
				pf.container.Put(t.id, key)
			}
			close(t.done)
		}(task)
	}
}

// waitForEVKs blocks until all specified EVKs are available in the container.
func (pf *Prefetcher) waitForEVKs(evkIDs []EVKIdentifier) {
	for _, id := range evkIDs {
		// Find the pending task for this EVK
		pf.mu.Lock()
		var task *loadTask
		for _, t := range pf.pending {
			if t.id == id {
				task = t
				break
			}
		}
		pf.mu.Unlock()

		if task != nil {
			start := time.Now()
			<-task.done // Block until loaded
			stall := time.Since(start)

			pf.mu.Lock()
			pf.stallTime += stall
			pf.mu.Unlock()
		}
		// If no task found, the EVK should already be in the container
		// (loaded in a previous cycle or pre-loaded).
	}

	// Clean up completed tasks
	pf.mu.Lock()
	var remaining []*loadTask
	for _, t := range pf.pending {
		select {
		case <-t.done:
			// completed, drop it
		default:
			remaining = append(remaining, t)
		}
	}
	pf.pending = remaining
	pf.mu.Unlock()
}
