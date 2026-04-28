package hesync

import (
	"fmt"
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

	// Metrics
	totalLoadTime time.Duration
	totalEvalTime time.Duration
	numCalls      int
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
		btps:   btps,
		store:  store,
		rlk:    rlk,
		galEls: galEls,
		rtks:   rtks,
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

// loadAndBind pages boot rotkeys in from disk and rebinds them on every
// managed bootstrapper. Returns load elapsed time.
func (p *PagedBootstrapper) loadAndBind() time.Duration {
	loadStart := time.Now()
	keys := make(map[uint64]*rlwe.SwitchingKey, len(p.galEls))
	for _, galEl := range p.galEls {
		id := EVKIdentifier{Type: RotationKey, GaloisEl: galEl}
		swk, err := p.store.Load(id)
		if err != nil {
			panic(fmt.Errorf("hesync: load boot key gal=%d: %w", galEl, err))
		}
		keys[galEl] = swk
	}
	p.rtks.Keys = keys
	elapsed := time.Since(loadStart)
	p.totalLoadTime += elapsed

	for _, btp := range p.btps {
		if err := btp.SetKeys(ckks.BootstrappingKey{Rlk: p.rlk, Rtks: p.rtks}); err != nil {
			panic(fmt.Errorf("hesync: set boot keys: %w", err))
		}
	}
	return elapsed
}

// freeKeys drops all switching-key references so their byte buffers can be GC'd.
func (p *PagedBootstrapper) freeKeys() {
	for k := range p.rtks.Keys {
		delete(p.rtks.Keys, k)
	}
}

// BootstrappConv_CtoS pages keys in, runs the CtoS half, and pages keys out.
func (p *PagedBootstrapper) BootstrappConv_CtoS(btpIdx int, ct *ckks.Ciphertext) (*ckks.Ciphertext, *ckks.Ciphertext, float64) {
	if btpIdx < 0 || btpIdx >= len(p.btps) {
		panic(fmt.Errorf("hesync: btpIdx %d out of range", btpIdx))
	}
	p.loadAndBind()
	evalStart := time.Now()
	a, b, c := p.btps[btpIdx].BootstrappConv_CtoS(ct)
	p.totalEvalTime += time.Since(evalStart)
	p.numCalls++
	p.freeKeys()
	return a, b, c
}

// BootstrappConv_StoC pages keys in, runs the StoC half, and pages keys out.
func (p *PagedBootstrapper) BootstrappConv_StoC(btpIdx int, ct0, ct1 *ckks.Ciphertext) *ckks.Ciphertext {
	if btpIdx < 0 || btpIdx >= len(p.btps) {
		panic(fmt.Errorf("hesync: btpIdx %d out of range", btpIdx))
	}
	p.loadAndBind()
	evalStart := time.Now()
	out := p.btps[btpIdx].BootstrappConv_StoC(ct0, ct1)
	p.totalEvalTime += time.Since(evalStart)
	p.freeKeys()
	return out
}

// Bootstrapp loads boot rotkeys, runs the full bootstrap on the given
// bootstrapper index, and frees keys before returning.
func (p *PagedBootstrapper) Bootstrapp(btpIdx int, ct *ckks.Ciphertext) *ckks.Ciphertext {
	if btpIdx < 0 || btpIdx >= len(p.btps) {
		panic(fmt.Errorf("hesync: btpIdx %d out of range", btpIdx))
	}
	p.loadAndBind()
	evalStart := time.Now()
	out := p.btps[btpIdx].Bootstrapp(ct)
	p.totalEvalTime += time.Since(evalStart)
	p.numCalls++
	p.freeKeys()
	return out
}

// TotalLoadTime returns cumulative time spent loading boot rotkeys from disk.
func (p *PagedBootstrapper) TotalLoadTime() time.Duration { return p.totalLoadTime }

// TotalEvalTime returns cumulative time spent inside ckks.Bootstrapp (excluding load).
func (p *PagedBootstrapper) TotalEvalTime() time.Duration { return p.totalEvalTime }

// NumCalls returns the number of Bootstrapp invocations.
func (p *PagedBootstrapper) NumCalls() int { return p.numCalls }
