package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/hesync"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
)

// hesyncEagerPrefetch controls whether the PagedBootstrapper kicks off
// async boot-key loads after each Bootstrapp returns. Defaults to on.
// Set HESYNC_EAGER_PREFETCH=0 (or false/no/off) to disable — useful for
// the bounding experiment that measures how much PeakRSS is being held
// hostage by eager prefetch and how much latency that recovers.
func hesyncEagerPrefetch() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("HESYNC_EAGER_PREFETCH")))
	switch v {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// HESync now wraps three resident key sets:
//   - cont.evaluator        (main non-boot rotation keys + rlk) — prefetched via plan
//   - cont.pack_evaluator   (pack-layer rotation keys)          — prefetched via plan
//   - cont.btp* bootstrappers (boot rotation keys)              — paged around each bootstrap
//
// Each keyset has its own on-disk EVKStore under hesyncStoreRoot.

const hesyncStoreRoot = "../hesync_evks"

// hesyncUseDirectIO opens EVK files with O_DIRECT so EVK bytes never enter
// the OS page cache. This avoids polluting DRAM with key material that is
// only read once per use, at the cost of stricter alignment overhead in the
// store implementation. Linux-only; flip to false on other platforms.
const hesyncUseDirectIO = true

type hesyncRuntime struct {
	mainStore *hesync.EVKStore
	packStore *hesync.EVKStore
	bootStore *hesync.EVKStore

	mainEvalKey rlwe.EvaluationKey
	packEvalKey rlwe.EvaluationKey

	mainPrefetcher *hesync.Prefetcher
	packPrefetcher *hesync.Prefetcher

	mainContainer *hesync.EVKContainer
	packContainer *hesync.EVKContainer

	paged *hesync.PagedBootstrapper
}

func (r *hesyncRuntime) peakEVKs() int {
	if r.mainContainer == nil {
		return 0
	}
	n := r.mainContainer.PeakCount()
	if r.packContainer != nil {
		n += r.packContainer.PeakCount()
	}
	return n
}

// saveAllKeysets persists main/pack/boot keys to three separate on-disk stores.
func saveAllKeysets(cont *context) (main, pack, boot *hesync.EVKStore, err error) {
	main, err = hesync.NewEVKStore(filepath.Join(hesyncStoreRoot, "main"))
	if err != nil {
		return
	}
	if hesyncUseDirectIO {
		main.EnableDirectIO()
	}
	if err = main.SaveAll(cont.rlk, cont.rotkeys); err != nil {
		return
	}

	if cont.packRtks != nil {
		pack, err = hesync.NewEVKStore(filepath.Join(hesyncStoreRoot, "pack"))
		if err != nil {
			return
		}
		if hesyncUseDirectIO {
			pack.EnableDirectIO()
		}
		// pack_evaluator has no rlk (nil is fine)
		if err = pack.SaveAll(nil, cont.packRtks); err != nil {
			return
		}
	}

	if cont.btpRtks != nil {
		boot, err = hesync.NewEVKStore(filepath.Join(hesyncStoreRoot, "boot"))
		if err != nil {
			return
		}
		if hesyncUseDirectIO {
			boot.EnableDirectIO()
		}
		// boot rotkeys share rlk with main; save rlk there only.
		if err = boot.SaveAll(nil, cont.btpRtks); err != nil {
			return
		}
	}
	return
}

// buildPagedBootstrapper constructs a HESync PagedBootstrapper around all
// bootstrapper instances on cont. Returns nil if no boot store available.
func buildPagedBootstrapper(cont *context, bootStore *hesync.EVKStore) *hesync.PagedBootstrapper {
	if bootStore == nil {
		return nil
	}
	btps := []*ckks.Bootstrapper{}
	for _, btp := range []*ckks.Bootstrapper{cont.btp, cont.btp2, cont.btp3, cont.btp4, cont.btp5} {
		if btp != nil {
			btps = append(btps, btp)
		}
	}
	if len(btps) == 0 {
		return nil
	}
	return hesync.NewPagedBootstrapper(btps, bootStore, cont.rlk, cont.params)
}

// runHESyncPipeline drives the full HESync pipeline:
//  1. Save 3 keysets to disk.
//  2. Trace phase: two tracer evaluators replace cont.evaluator and
//     cont.pack_evaluator; hesyncTracing=true short-circuits bootstrap.
//  3. Profile main + pack separately against their respective stores.
//  4. For each plan criterion, run with:
//     - HESyncEvaluator wrapping cont.evaluator  (main prefetcher)
//     - HESyncEvaluator wrapping cont.pack_evaluator (pack prefetcher)
//     - PagedBootstrapper pinned to cont.btp* (boot keys paged per call)
func runHESyncPipeline(cont *context, label string, runIter func(iters int), totalIters int) {
	fmt.Println()
	fmt.Println("=======================================================")
	fmt.Println("  HESync:", label)
	fmt.Println("=======================================================")

	origMainEval := cont.evaluator
	origPackEval := cont.pack_evaluator

	mainEvalKey := rlwe.EvaluationKey{Rlk: cont.rlk, Rtks: cont.rotkeys}
	packEvalKey := rlwe.EvaluationKey{Rtks: cont.packRtks}

	// --- Step 1: save all keysets ---
	mainStore, packStore, bootStore, err := saveAllKeysets(cont)
	if err != nil {
		panic(fmt.Errorf("hesync: save keysets: %w", err))
	}
	evkSizeMB := float64(mainStore.KeySize()) / (1024 * 1024)
	ioMode := "buffered"
	if mainStore.DirectIOEnabled() {
		ioMode = "O_DIRECT"
	}
	fmt.Printf("HESync: saved keys (main=%d, pack=%d, boot=%d), per-main-key %.2f MB, io=%s\n",
		mainStore.Count(),
		countIf(packStore),
		countIf(bootStore),
		evkSizeMB,
		ioMode)

	// --- Step 2: combined baseline + trace pass (using InstrumentingEvaluator) ---
	// This replaces the old "fake-tracer swap" design. We run the real workload
	// once, with cont.evaluator and cont.pack_evaluator temporarily wrapped in
	// InstrumentingEvaluators that record a trace while delegating every op to
	// the real inner evaluator. Bootstrap runs for real — no short-circuit.
	mainInst := hesync.NewInstrumentingEvaluator(origMainEval, cont.params)
	packInst := hesync.NewInstrumentingEvaluator(origPackEval, cont.packParams)
	cont.evaluator = mainInst
	cont.pack_evaluator = packInst
	hesyncSkipDecrypt = false

	runtime.GC()
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	baseStart := time.Now()
	runIter(totalIters)
	baseLatency := time.Since(baseStart)
	runtime.ReadMemStats(&memAfter)
	baseHeapMB := float64(memAfter.HeapSys) / (1024 * 1024)
	baseRSS := readPeakRSSKB()

	mainTrace := mainInst.GetTrace()
	packTrace := packInst.GetTrace()
	fmt.Printf("Baseline+trace: latency=%v heapSys=%.0f MB peakRSS=%d KB  traced main=%d ops pack=%d ops\n",
		baseLatency.Round(time.Millisecond), baseHeapMB, baseRSS,
		len(mainTrace.Entries), len(packTrace.Entries))

	// Restore real evaluators.
	cont.evaluator = origMainEval
	cont.pack_evaluator = origPackEval

	// Reset VmHWM so subsequent peakRSS readings (postArm + per-criterion)
	// reflect only post-baseline allocations rather than the trace-pass peak.
	resetVmHWM()

	// --- Step 3: profile ---
	profileStart := time.Now()
	mainProfiler := hesync.NewProfiler(cont.params)
	mainProfiler.SetIterations(3)
	mainProfile := mainProfiler.ProfileFromTrace(mainTrace, mainEvalKey, mainStore)

	var packProfile *hesync.Profile
	if len(packTrace.Entries) > 0 {
		packProfiler := hesync.NewProfiler(cont.packParams)
		packProfiler.SetIterations(3)
		packProfile = packProfiler.ProfileFromTrace(packTrace, packEvalKey, packStore)
	}
	profileLatency := time.Since(profileStart)
	fmt.Printf("HESync: profile complete in %v\n", profileLatency)

	// --- Step 4: install paged bootstrapper and free the original boot keys ---
	pagedBtp = buildPagedBootstrapper(cont, bootStore)
	if pagedBtp == nil {
		fmt.Println("HESync: WARN boot store missing; bootstrap keys remain resident")
	} else {
		// Transition bootstrappers onto the paged rtks shell, then drop our
		// external reference so the original boot keys can be GC'd.
		pagedBtp.Arm()
		cont.btpRtks = nil
		// Boot keys are loaded as one atomic unit, so the Tracer/Planner pipeline
		// can't schedule them at sub-bootstrap granularity. Three walk-arounds
		// stack to hide the cost:
		//   - Eager prefetch: kick off an async load right after each freeKeys
		//     so the next call's load overlaps with workload compute.
		//   - Hold keys across the CtoS/StoC pair: avoid the redundant StoC
		//     reload (the same keys are needed twice in a row, separated only
		//     by ReLU).
		//   - Parallel disk I/O within a single load (set via SetLoadParallelism).
		pagedBtp.SetLoadParallelism(8)
		eager := hesyncEagerPrefetch()
		if eager {
			pagedBtp.EnableEagerPrefetch()
		}
		fmt.Printf("HESync: paged bootstrapper armed (eager prefetch=%v)\n", eager)
	}

	// --- Step 5: drop ALL resident key references so Go can reclaim them ---
	// After this point, the only resident key material is what the paged
	// bootstrapper holds (briefly, around each Bootstrapp call) and what each
	// criterion's Prefetcher loads on demand. We capture the galois-element
	// list first because PreparePermuteNTTIndex needs it inside the loop.
	mainGalEls := collectGalEls(cont.rotkeys)
	packGalEls := collectGalEls(cont.packRtks)

	cont.evaluator = nil
	cont.pack_evaluator = nil
	origMainEval = nil
	origPackEval = nil
	cont.rotkeys = nil
	cont.packRtks = nil
	cont.rlk = nil
	mainEvalKey = rlwe.EvaluationKey{}
	packEvalKey = rlwe.EvaluationKey{}

	// Force GC, then ask the runtime to release pages back to the OS.
	// On Linux, Go's default unmap path uses MADV_FREE, which leaves the
	// pages charged to RSS until the kernel reclaims them under pressure.
	// Run with GODEBUG=madvdontneed=1 to make FreeOSMemory issue
	// MADV_DONTNEED instead, so RSS drops immediately.
	runtime.GC()
	debug.FreeOSMemory()

	// Reset VmHWM so postArm and per-criterion peakRSS reflect only
	// allocations observed *after* keysets were dropped.
	resetVmHWM()
	fmt.Printf("HESync: bootstrap keys paged + main/pack keysets dropped. postArm peakRSS=%d KB\n",
		readPeakRSSKB())

	// --- Step 6: run per criterion ---
	criteria := []hesync.PlanCriterion{
		hesync.CriterionLevel0,
		hesync.CriterionHalfMax,
		hesync.CriterionMaxLevel,
		hesync.CriterionPerTrace,
		hesync.CriterionLazyLoad,
	}

	type row struct {
		criterion hesync.PlanCriterion
		latency   time.Duration
		peakEVKs  int
		stall     time.Duration
		bootLoad  time.Duration // critical-path boot-key load time
		bootAsync time.Duration // boot-key load time hidden by eager prefetch
		rssKB     int64
		heapMB    float64
	}
	rows := make([]row, 0, len(criteria))

	for _, crit := range criteria {
		mainPlan := hesync.GeneratePlan(mainTrace, mainProfile, crit)
		mainContainer := hesync.NewEVKContainer()
		innerMain := ckks.NewEvaluator(cont.params, rlwe.EvaluationKey{
			Rlk:  mainContainer.RelinearizationKey(),
			Rtks: mainContainer.RotationKeySet(),
		})
		if len(mainGalEls) > 0 {
			innerMain.PreparePermuteNTTIndex(mainGalEls)
		}
		mainPrefetcher := hesync.NewPrefetcher(mainPlan, mainStore, mainContainer)
		cont.evaluator = hesync.NewHESyncEvaluator(innerMain, mainPrefetcher)

		var packContainer *hesync.EVKContainer
		var packPrefetcher *hesync.Prefetcher
		if packProfile != nil && len(packGalEls) > 0 {
			packPlan := hesync.GeneratePlan(packTrace, packProfile, crit)
			packContainer = hesync.NewEVKContainer()
			innerPack := ckks.NewEvaluator(cont.packParams, rlwe.EvaluationKey{
				Rtks: packContainer.RotationKeySet(),
			})
			innerPack.PreparePermuteNTTIndex(packGalEls)
			packPrefetcher = hesync.NewPrefetcher(packPlan, packStore, packContainer)
			cont.pack_evaluator = hesync.NewHESyncEvaluator(innerPack, packPrefetcher)
		} else {
			cont.pack_evaluator = nil
		}

		hesyncSkipDecrypt = false
		runtime.GC()
		debug.FreeOSMemory()
		// Reset VmHWM so this criterion's PeakRSS reflects only its own peak,
		// not the cumulative high-water from earlier passes / criteria.
		resetVmHWM()
		runtime.ReadMemStats(&memBefore)
		startT := time.Now()
		runIter(totalIters)
		lat := time.Since(startT)
		runtime.ReadMemStats(&memAfter)

		stall := mainPrefetcher.StallTime()
		if packPrefetcher != nil {
			stall += packPrefetcher.StallTime()
		}
		peakEVKs := mainContainer.PeakCount()
		if packContainer != nil {
			peakEVKs += packContainer.PeakCount()
		}
		var bootLoad, bootAsync time.Duration
		if pagedBtp != nil {
			bootLoad = pagedBtp.TotalLoadTime()
			bootAsync = pagedBtp.TotalAsyncLoadTime()
		}
		rows = append(rows, row{
			criterion: crit,
			latency:   lat,
			peakEVKs:  peakEVKs,
			stall:     stall,
			bootLoad:  bootLoad,
			bootAsync: bootAsync,
			rssKB:     readPeakRSSKB(),
			heapMB:    float64(memAfter.HeapSys) / (1024 * 1024),
		})

		mainContainer.Reset()
		if packContainer != nil {
			packContainer.Reset()
		}
	}

	// Snapshot per-btp call counts before clearing the paged bootstrapper.
	// Counts are cumulative across all criteria executed above; with a
	// single criterion they reflect one full workload run.
	var perBtpCtoS, perBtpStoC, perBtpFull []int
	if pagedBtp != nil {
		perBtpCtoS, perBtpStoC, perBtpFull = pagedBtp.PerBtpCalls()
	}

	// Caller does not reuse cont after this point; original evaluator
	// references were dropped above so leave them nil. Just clear the
	// paged-bootstrap pointer so a subsequent pipeline run doesn't see it.
	pagedBtp = nil

	// --- Step 7: report ---
	fmt.Println()
	fmt.Println("===============  HESync Results  ===============")
	fmt.Printf("Workload:       %s\n", label)
	fmt.Printf("Iterations/run: %d\n", totalIters)
	fmt.Printf("Trace (main):   %d ops\n", len(mainTrace.Entries))
	fmt.Printf("Trace (pack):   %d ops\n", len(packTrace.Entries))
	fmt.Printf("Baseline:       latency=%v  heapSys=%.0f MB  peakRSS=%d KB\n",
		baseLatency.Round(time.Millisecond), baseHeapMB, baseRSS)
	fmt.Printf("%-10s %12s %10s %10s %12s %12s %12s %10s\n",
		"Criterion", "Latency", "PeakEVKs", "Stall", "BootLoad", "BootAsync", "PeakRSS(KB)", "HeapSys(MB)")
	for _, r := range rows {
		fmt.Printf("%-10s %12v %10d %10v %12v %12v %12d %10.0f\n",
			r.criterion,
			r.latency.Round(time.Millisecond),
			r.peakEVKs,
			r.stall.Round(time.Millisecond),
			r.bootLoad.Round(time.Millisecond),
			r.bootAsync.Round(time.Millisecond),
			r.rssKB,
			r.heapMB)
	}

	if len(perBtpCtoS) > 0 {
		fmt.Println()
		fmt.Println("---  Per-btp call counts (cumulative across criteria)  ---")
		fmt.Printf("%-7s %10s %10s %10s %10s\n", "btpIdx", "CtoS", "StoC", "Full", "Total")
		var totCtoS, totStoC, totFull int
		for i := range perBtpCtoS {
			tot := perBtpCtoS[i] + perBtpStoC[i] + perBtpFull[i]
			fmt.Printf("%-7d %10d %10d %10d %10d\n",
				i, perBtpCtoS[i], perBtpStoC[i], perBtpFull[i], tot)
			totCtoS += perBtpCtoS[i]
			totStoC += perBtpStoC[i]
			totFull += perBtpFull[i]
		}
		fmt.Printf("%-7s %10d %10d %10d %10d\n", "all",
			totCtoS, totStoC, totFull, totCtoS+totStoC+totFull)
	}
	fmt.Println("================================================")
}

func countIf(s *hesync.EVKStore) int {
	if s == nil {
		return 0
	}
	return s.Count()
}

// collectGalEls extracts the galois-element keys from a RotationKeySet so
// callers can drop their reference to the keyset itself while still being
// able to (re)build PreparePermuteNTTIndex tables.
func collectGalEls(rks *rlwe.RotationKeySet) []uint64 {
	if rks == nil {
		return nil
	}
	out := make([]uint64, 0, len(rks.Keys))
	for g := range rks.Keys {
		out = append(out, g)
	}
	return out
}

// resetVmHWM resets the kernel-tracked peak RSS by writing "5" to
// /proc/self/clear_refs (CLEAR_REFS_MM_HIWATER_RSS, Linux 4.0+).
// After this, /proc/self/status:VmHWM reflects only allocations
// observed after the reset.
func resetVmHWM() {
	if err := os.WriteFile("/proc/self/clear_refs", []byte("5\n"), 0); err != nil {
		fmt.Printf("HESync: WARN resetVmHWM failed: %v\n", err)
	}
}

func readPeakRSSKB() int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, ln := range splitLines(string(data)) {
		if len(ln) >= 6 && ln[:6] == "VmHWM:" {
			var kb int64
			fmt.Sscanf(ln, "VmHWM: %d kB", &kb)
			return kb
		}
	}
	return 0
}

func splitLines(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// testResNet_crop_sparse_hesync runs the wide-factor-1 resnet workload under
// the full HESync pipeline (main eval + pack eval + paged bootstrap).
func testResNet_crop_sparse_hesync(st, end, ker_wid, depth int, debug, cf100 bool) {
	in_wids := []int{32, 16, 8}
	raw_in_wids := []int{32 - ker_wid/2, 16 - ker_wid/2, 8 - ker_wid/2}
	cont := newContext(16, ker_wid, in_wids, raw_in_wids, true, "Resnet_crop_sparse")

	run := func(iters int) {
		if iters == 1 {
			testResNet_crop_sparse(st, st+1, ker_wid, depth, debug, cf100, cont)
			return
		}
		testResNet_crop_sparse(st, end, ker_wid, depth, debug, cf100, cont)
	}
	runHESyncPipeline(cont, fmt.Sprintf("resnet ker=%d depth=%d cf100=%v", ker_wid, depth, cf100), run, end-st)
}

// testResNet_crop_sparse_wide_hesync runs wide-factor 2/3 resnet under HESync.
func testResNet_crop_sparse_wide_hesync(st, end, ker_wid, depth, wide_case int, debug, cf100 bool) {
	kind := "Resnet_crop_sparse_wide2"
	if wide_case == 3 {
		kind = "Resnet_crop_sparse_wide3"
	}
	in_wids := []int{32, 16, 8}
	raw_in_wids := []int{32 - ker_wid/2, 16 - ker_wid/2, 8 - ker_wid/2}
	cont := newContext(16, ker_wid, in_wids, raw_in_wids, true, kind)

	run := func(iters int) {
		if iters == 1 {
			testResNet_crop_sparse_wide(st, st+1, ker_wid, depth, wide_case, debug, cf100, cont)
			return
		}
		testResNet_crop_sparse_wide(st, end, ker_wid, depth, wide_case, debug, cf100, cont)
	}
	runHESyncPipeline(cont, fmt.Sprintf("resnet_wide%d ker=%d depth=%d cf100=%v", wide_case, ker_wid, depth, cf100), run, end-st)
}
