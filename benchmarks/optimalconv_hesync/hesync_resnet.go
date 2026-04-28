package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/hesync"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
)

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
//   1. Save 3 keysets to disk.
//   2. Trace phase: two tracer evaluators replace cont.evaluator and
//      cont.pack_evaluator; hesyncTracing=true short-circuits bootstrap.
//   3. Profile main + pack separately against their respective stores.
//   4. For each plan criterion, run with:
//        - HESyncEvaluator wrapping cont.evaluator  (main prefetcher)
//        - HESyncEvaluator wrapping cont.pack_evaluator (pack prefetcher)
//        - PagedBootstrapper pinned to cont.btp* (boot keys paged per call)
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
		runtime.GC()
		fmt.Printf("HESync: bootstrap keys paged (resident only during Bootstrapp calls). postArm peakRSS=%d KB\n",
			readPeakRSSKB())
	}

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
		bootLoad  time.Duration
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
		if cont.rotkeys != nil {
			galEls := make([]uint64, 0, len(cont.rotkeys.Keys))
			for g := range cont.rotkeys.Keys {
				galEls = append(galEls, g)
			}
			innerMain.PreparePermuteNTTIndex(galEls)
		}
		mainPrefetcher := hesync.NewPrefetcher(mainPlan, mainStore, mainContainer)
		cont.evaluator = hesync.NewHESyncEvaluator(innerMain, mainPrefetcher)

		var packContainer *hesync.EVKContainer
		var packPrefetcher *hesync.Prefetcher
		if packProfile != nil && cont.packRtks != nil {
			packPlan := hesync.GeneratePlan(packTrace, packProfile, crit)
			packContainer = hesync.NewEVKContainer()
			innerPack := ckks.NewEvaluator(cont.packParams, rlwe.EvaluationKey{
				Rtks: packContainer.RotationKeySet(),
			})
			galEls := make([]uint64, 0, len(cont.packRtks.Keys))
			for g := range cont.packRtks.Keys {
				galEls = append(galEls, g)
			}
			innerPack.PreparePermuteNTTIndex(galEls)
			packPrefetcher = hesync.NewPrefetcher(packPlan, packStore, packContainer)
			cont.pack_evaluator = hesync.NewHESyncEvaluator(innerPack, packPrefetcher)
		} else {
			cont.pack_evaluator = origPackEval
		}

		hesyncSkipDecrypt = false
		runtime.GC()
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
		var bootLoad time.Duration
		if pagedBtp != nil {
			bootLoad = pagedBtp.TotalLoadTime()
		}
		rows = append(rows, row{
			criterion: crit,
			latency:   lat,
			peakEVKs:  peakEVKs,
			stall:     stall,
			bootLoad:  bootLoad,
			rssKB:     readPeakRSSKB(),
			heapMB:    float64(memAfter.HeapSys) / (1024 * 1024),
		})

		mainContainer.Reset()
		if packContainer != nil {
			packContainer.Reset()
		}
	}

	// restore
	cont.evaluator = origMainEval
	cont.pack_evaluator = origPackEval
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
	fmt.Printf("%-10s %12s %10s %10s %10s %12s %10s\n",
		"Criterion", "Latency", "PeakEVKs", "Stall", "BootLoad", "PeakRSS(KB)", "HeapSys(MB)")
	for _, r := range rows {
		fmt.Printf("%-10s %12v %10d %10v %10v %12d %10.0f\n",
			r.criterion,
			r.latency.Round(time.Millisecond),
			r.peakEVKs,
			r.stall.Round(time.Millisecond),
			r.bootLoad.Round(time.Millisecond),
			r.rssKB,
			r.heapMB)
	}
	fmt.Println("================================================")
}

func countIf(s *hesync.EVKStore) int {
	if s == nil {
		return 0
	}
	return s.Count()
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
