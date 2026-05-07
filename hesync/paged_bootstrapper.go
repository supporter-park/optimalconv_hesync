package hesync

import (
	"fmt"
	"sync"
	"time"

	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
)

// PagedBootstrapper wraps one or more ckks.Bootstrapper instances that share a
// single bootstrapping RotationKeySet. It implements HESync's atomic "page-in
// boot keys on demand, page-out after Bootstrapp returns" strategy.
//
// The expensive precomputed data (DFT matrices, sine polynomial, permutation
// indexes) lives on the inner *ckks.Bootstrapper and persists across calls.
// Only the switching-key byte buffers are loaded lazily from disk.
//
// Bootstrap itself is still treated as atomic — prefetching happens at the
// granularity of a whole Bootstrapp invocation, not its internal rotations.
// This means boot keys are entirely resident for the duration of one bootstrap
// but entirely absent between bootstraps.
type PagedBootstrapper struct {
	btps    []*ckks.Bootstrapper // all bootstrappers sharing a single boot rtks
	store   *EVKStore
	rlk     *rlwe.RelinearizationKey
	galEls  []uint64
	rtks    *rlwe.RotationKeySet // shared empty shell whose .Keys is swapped

	// Metrics. totalLoadTime counts only critical-path load time (sync loads
	// plus awaitPrefetch wait time). Loads that complete entirely off the
	// critical path are tallied in totalAsyncLoadTime instead.
	totalLoadTime      time.Duration
	totalAsyncLoadTime time.Duration
	totalEvalTime      time.Duration
	numCalls           int

	// Per-btp call counters. Indexed by btpIdx (the same index passed to
	// the public Bootstrapp* methods). Used to scope per-btp routing wins
	// — if one btp dominates, loading only its keys saves little; if calls
	// spread across btps with disjoint key sets, savings are larger.
	callsCtoS []int
	callsStoC []int
	callsFull []int

	// Eager-prefetch state.
	eagerPrefetch bool
	prefetchMu    sync.Mutex
	prefetchDone  chan struct{} // closed when in-flight async load finishes; nil if no prefetch

	// midPair, when true, means BootstrappConv_CtoS just ran and the keys
	// have been kept resident in anticipation of the matching
	// BootstrappConv_StoC call. The next StoC will skip pageInForCall and
	// reuse the resident keys; CtoS sets it, StoC clears it.
	midPair bool

	// loadParallelism controls how many goroutines fan out reads from the
	// EVK store inside a single loadAndBindCore. Set via SetLoadParallelism;
	// defaults to 1 (serial reads, original behavior).
	loadParallelism int
}

// NewPagedBootstrapper constructs a PagedBootstrapper managing the given
// Bootstrappers (they must all share the same bootstrapping key set).
//
// store must already contain all boot rotkeys (caller is expected to have
// SaveAll'd them). rlk is retained in memory (it is small — typically a few
// MB — and required by every bootstrap call).
//
// The Galois elements are derived from the first bootstrapper's
// RotKeyIndex using params.GaloisElementForColumnRotationBy.
func NewPagedBootstrapper(
	btps []*ckks.Bootstrapper,
	store *EVKStore,
	rlk *rlwe.RelinearizationKey,
	params ckks.Parameters,
) *PagedBootstrapper {
	if len(btps) == 0 {
		panic("hesync: PagedBootstrapper requires at least one bootstrapper")
	}

	// Collect the union of all rotKeyIndexes across all bootstrappers.
	seen := make(map[int]struct{})
	for _, btp := range btps {
		for _, k := range btp.RotKeyIndex() {
			seen[k] = struct{}{}
		}
	}
	galEls := make([]uint64, 0, len(seen))
	for k := range seen {
		galEls = append(galEls, params.GaloisElementForColumnRotationBy(k))
	}
	// Galois element for conjugation is also used by the bootstrapper.
	galEls = append(galEls, params.GaloisElementForRowRotation())

	// Precompute permutation indexes on every bootstrapper's evaluator so that
	// rotations work even when the SwitchingKey map is empty (indexes depend
	// only on galois element, not key value).
	for _, btp := range btps {
		btp.PreparePermuteNTTIndex(galEls)
	}

	// Shared empty shell rtks — SetKeys rebinds .Keys before each call.
	rtks := &rlwe.RotationKeySet{Keys: make(map[uint64]*rlwe.SwitchingKey)}

	return &PagedBootstrapper{
		btps:      btps,
		store:     store,
		rlk:       rlk,
		galEls:    galEls,
		rtks:      rtks,
		callsCtoS: make([]int, len(btps)),
		callsStoC: make([]int, len(btps)),
		callsFull: make([]int, len(btps)),
	}
}

// Arm transitions each bootstrapper off its externally-held RotationKeySet
// and onto the PagedBootstrapper's shared shell rtks, so the external rotkeys
// reference can be dropped (and its backing memory freed) by the caller.
//
// Callers should invoke Arm once after construction, then nil out their
// external reference (e.g. cont.btpRtks = nil) and trigger GC. Between Arm
// and the first Bootstrapp call, the managed bootstrappers have no keys
// loaded; they cannot be invoked in that interval except via this
// PagedBootstrapper.
func (p *PagedBootstrapper) Arm() {
	p.loadAndBind()
	p.freeKeys()
	// Subtract the initial load time from metrics — it's a setup cost,
	// not a per-call cost.
	p.totalLoadTime = 0
}

// loadAndBindCore pages boot rotkeys in from disk and rebinds them on every
// managed bootstrapper. Returns load elapsed time without touching metrics.
// Callers decide whether the elapsed time is critical-path or async.
//
// When loadParallelism > 1 the disk reads fan out across that many worker
// goroutines (the EVK store's per-id Load is independent and safe for
// concurrent calls). Each in-flight worker holds one key in memory so the
// transient extra footprint is at most parallelism × keysize.
func (p *PagedBootstrapper) loadAndBindCore() time.Duration {
	loadStart := time.Now()
	keys := make(map[uint64]*rlwe.SwitchingKey, len(p.galEls))

	parallelism := p.loadParallelism
	if parallelism < 1 {
		parallelism = 1
	}
	if parallelism == 1 {
		for _, galEl := range p.galEls {
			id := EVKIdentifier{Type: RotationKey, GaloisEl: galEl}
			swk, err := p.store.Load(id)
			if err != nil {
				panic(fmt.Errorf("hesync: load boot key gal=%d: %w", galEl, err))
			}
			keys[galEl] = swk
		}
	} else {
		type result struct {
			galEl uint64
			swk   *rlwe.SwitchingKey
			err   error
		}
		jobs := make(chan uint64, len(p.galEls))
		results := make(chan result, len(p.galEls))
		var wg sync.WaitGroup
		for w := 0; w < parallelism; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for galEl := range jobs {
					id := EVKIdentifier{Type: RotationKey, GaloisEl: galEl}
					swk, err := p.store.Load(id)
					results <- result{galEl, swk, err}
				}
			}()
		}
		for _, galEl := range p.galEls {
			jobs <- galEl
		}
		close(jobs)
		wg.Wait()
		close(results)
		for r := range results {
			if r.err != nil {
				panic(fmt.Errorf("hesync: load boot key gal=%d: %w", r.galEl, r.err))
			}
			keys[r.galEl] = r.swk
		}
	}

	p.rtks.Keys = keys
	elapsed := time.Since(loadStart)

	for _, btp := range p.btps {
		if err := btp.SetKeys(ckks.BootstrappingKey{Rlk: p.rlk, Rtks: p.rtks}); err != nil {
			panic(fmt.Errorf("hesync: set boot keys: %w", err))
		}
	}
	return elapsed
}

// SetLoadParallelism configures how many goroutines split a single
// loadAndBind across the EVK store. Useful when the disk subsystem can
// service concurrent reads faster than serial ones (NVMe, parallel HDD
// arrays). Calling with n <= 1 reverts to serial reads. Safe to call once
// before any Bootstrapp invocation.
func (p *PagedBootstrapper) SetLoadParallelism(n int) {
	if n < 1 {
		n = 1
	}
	p.loadParallelism = n
}

// loadAndBind is the synchronous (critical-path) load entry point.
func (p *PagedBootstrapper) loadAndBind() time.Duration {
	elapsed := p.loadAndBindCore()
	p.totalLoadTime += elapsed
	return elapsed
}

// kickoffPrefetch starts an async loadAndBindCore on a goroutine if no
// prefetch is currently in flight. The goroutine writes p.rtks.Keys and
// calls SetKeys on each managed bootstrapper. Synchronization with the
// next pageInForCall is via the prefetchDone channel.
func (p *PagedBootstrapper) kickoffPrefetch() {
	p.prefetchMu.Lock()
	if p.prefetchDone != nil {
		p.prefetchMu.Unlock()
		return
	}
	done := make(chan struct{})
	p.prefetchDone = done
	p.prefetchMu.Unlock()

	go func() {
		elapsed := p.loadAndBindCore()
		p.prefetchMu.Lock()
		p.totalAsyncLoadTime += elapsed
		p.prefetchMu.Unlock()
		close(done)
	}()
}

// awaitPrefetch blocks until the in-flight prefetch (if any) completes,
// counting the wait time as critical-path load time. If no prefetch is in
// flight, falls back to a synchronous load.
func (p *PagedBootstrapper) awaitPrefetch() {
	p.prefetchMu.Lock()
	done := p.prefetchDone
	p.prefetchDone = nil
	p.prefetchMu.Unlock()
	if done == nil {
		p.loadAndBind()
		return
	}
	waitStart := time.Now()
	<-done
	p.totalLoadTime += time.Since(waitStart)
}

// pageInForCall is called by every Bootstrapp variant before invoking the
// underlying bootstrapper. It picks sync-load or await-prefetch based on
// whether eager prefetch is enabled.
func (p *PagedBootstrapper) pageInForCall() {
	if p.eagerPrefetch {
		p.awaitPrefetch()
	} else {
		p.loadAndBind()
	}
}

// pageOutAfterCall is called by every Bootstrapp variant after the
// underlying bootstrapper returns. It frees keys and, when eager prefetch
// is on, kicks off the next async load so it overlaps with the workload's
// next batch of main/pack ops.
func (p *PagedBootstrapper) pageOutAfterCall() {
	p.freeKeys()
	if p.eagerPrefetch {
		p.kickoffPrefetch()
	}
}

// EnableEagerPrefetch turns on async boot-key prefetching: after every
// Bootstrapp variant frees keys, a background goroutine starts loading
// them again so the next call's synchronous load is replaced by a much
// shorter wait (and often disappears entirely when the workload's
// pre-bootstrap work is longer than the load).
//
// Calling EnableEagerPrefetch immediately after Arm kicks off an initial
// prefetch so the very first Bootstrapp invocation also benefits.
//
// Memory cost: boot keys end up resident through most of the workload
// instead of only during each bootstrap. For the resnet-20 workload this
// adds ~27 GiB to PeakRSS in exchange for hiding ~19 minutes of disk I/O
// per criterion.
func (p *PagedBootstrapper) EnableEagerPrefetch() {
	p.eagerPrefetch = true
	p.kickoffPrefetch()
}

// TotalAsyncLoadTime returns cumulative wall time spent loading boot keys
// off the critical path (under eager prefetch). Useful as a denominator
// when reasoning about how much load was hidden.
func (p *PagedBootstrapper) TotalAsyncLoadTime() time.Duration {
	p.prefetchMu.Lock()
	defer p.prefetchMu.Unlock()
	return p.totalAsyncLoadTime
}

// freeKeys drops all switching-key references so their byte buffers can be GC'd.
func (p *PagedBootstrapper) freeKeys() {
	for k := range p.rtks.Keys {
		delete(p.rtks.Keys, k)
	}
}

// BootstrappConv_CtoS pages keys in and runs the CtoS half. Keys are held
// resident afterwards so the matching BootstrappConv_StoC can reuse them
// without a second load. (StoC is the one that finally pages keys out.)
func (p *PagedBootstrapper) BootstrappConv_CtoS(btpIdx int, ct *ckks.Ciphertext) (*ckks.Ciphertext, *ckks.Ciphertext, float64) {
	if btpIdx < 0 || btpIdx >= len(p.btps) {
		panic(fmt.Errorf("hesync: btpIdx %d out of range", btpIdx))
	}
	if !p.midPair {
		p.pageInForCall()
	}
	evalStart := time.Now()
	a, b, c := p.btps[btpIdx].BootstrappConv_CtoS(ct)
	p.totalEvalTime += time.Since(evalStart)
	p.numCalls++
	p.callsCtoS[btpIdx]++
	p.midPair = true // keys retained for the matching StoC
	return a, b, c
}

// BootstrappConv_StoC reuses the keys left resident by the matching CtoS
// (no reload), runs the StoC half, and pages keys out. If called outside
// a pair (no preceding CtoS) it falls back to a fresh load.
func (p *PagedBootstrapper) BootstrappConv_StoC(btpIdx int, ct0, ct1 *ckks.Ciphertext) *ckks.Ciphertext {
	if btpIdx < 0 || btpIdx >= len(p.btps) {
		panic(fmt.Errorf("hesync: btpIdx %d out of range", btpIdx))
	}
	if !p.midPair {
		p.pageInForCall()
	}
	evalStart := time.Now()
	out := p.btps[btpIdx].BootstrappConv_StoC(ct0, ct1)
	p.totalEvalTime += time.Since(evalStart)
	p.callsStoC[btpIdx]++
	p.midPair = false
	p.pageOutAfterCall()
	return out
}

// Bootstrapp loads boot rotkeys, runs the full bootstrap on the given
// bootstrapper index, and frees keys before returning.
func (p *PagedBootstrapper) Bootstrapp(btpIdx int, ct *ckks.Ciphertext) *ckks.Ciphertext {
	if btpIdx < 0 || btpIdx >= len(p.btps) {
		panic(fmt.Errorf("hesync: btpIdx %d out of range", btpIdx))
	}
	p.pageInForCall()
	evalStart := time.Now()
	out := p.btps[btpIdx].Bootstrapp(ct)
	p.totalEvalTime += time.Since(evalStart)
	p.numCalls++
	p.callsFull[btpIdx]++
	p.pageOutAfterCall()
	return out
}

// TotalLoadTime returns cumulative time spent loading boot rotkeys from disk.
func (p *PagedBootstrapper) TotalLoadTime() time.Duration { return p.totalLoadTime }

// TotalEvalTime returns cumulative time spent inside ckks.Bootstrapp (excluding load).
func (p *PagedBootstrapper) TotalEvalTime() time.Duration { return p.totalEvalTime }

// NumCalls returns the number of Bootstrapp invocations.
func (p *PagedBootstrapper) NumCalls() int { return p.numCalls }

// PerBtpCalls returns per-btp invocation counts split by entry point. Each
// returned slice has length len(btps); the i-th entry counts calls routed
// to btps[i]. Useful for scoping per-btp routing wins: if a single btp
// dominates, loading only its keys saves little.
func (p *PagedBootstrapper) PerBtpCalls() (ctoS, stoC, full []int) {
	ctoS = append(ctoS, p.callsCtoS...)
	stoC = append(stoC, p.callsStoC...)
	full = append(full, p.callsFull...)
	return
}
