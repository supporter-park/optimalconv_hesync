// measure_btp_precompute reports the byte size of bootstrap precompute
// (DFT matrices, sine polynomial, ctxpool, permutation tables) for the 5
// bootstrappers used by the resnet sparse workload.
//
// No keys are generated and no inference runs — only the bootstrappers'
// internal precompute. Runs in seconds.
package main

import (
	"fmt"
	"time"

	"github.com/supporter-park/optimalconv_hesync/ckks"
)

func mib(b int64) float64 { return float64(b) / (1024 * 1024) }

func main() {
	// Same parameter set as the resnet sparse workload (see newContext in
	// benchmarks/optimalconv_hesync/main.go).
	btpParams := ckks.DefaultBootstrapParams[6]
	btpParams.LogN = 16

	logSlotsList := []int{
		btpParams.LogN - 1,
		btpParams.LogN - 2,
		btpParams.LogN - 3,
		btpParams.LogN - 4,
		btpParams.LogN - 5,
	}

	totals := ckks.PrecomputeBreakdown{}
	fmt.Printf("%-7s %-9s %-9s %-9s %-8s %-8s %-9s %-9s %s\n",
		"LogSlots", "pDFT(MiB)", "pDFTInv", "permIdx", "ctxPool", "sine", "arcSine", "subTotal", "(#pDFT/#pDFTInv)")

	// Track unioned per-phase rotations so we can also report the
	// deduplicated peak across all 5 bootstrappers.
	unionSubSum := map[int]struct{}{}
	unionCtoS := map[int]struct{}{}
	unionStoC := map[int]struct{}{}
	addAll := func(set map[int]struct{}, xs []int) {
		for _, x := range xs {
			set[x] = struct{}{}
		}
	}

	for _, ls := range logSlotsList {
		btpParams.LogSlots = ls
		params, err := btpParams.Params()
		if err != nil {
			panic(err)
		}

		t0 := time.Now()
		btp := ckks.NewPrecomputeOnlyBootstrapper(params, btpParams)

		// Populate the evaluator's permutation index tables for every boot
		// rotation so PermuteIdxBytes reflects production residency.
		galEls := make([]uint64, 0, len(btp.RotKeyIndex())+1)
		for _, k := range btp.RotKeyIndex() {
			galEls = append(galEls, params.GaloisElementForColumnRotationBy(k))
		}
		galEls = append(galEls, params.GaloisElementForRowRotation())
		btp.PreparePermuteNTTIndex(galEls)
		buildElapsed := time.Since(t0)

		bd := btp.PrecomputeBreakdown()
		fmt.Printf("%-7d %9.1f %9.1f %9.1f %8.1f %8.1f %9.1f %9.1f  (%d/%d) build=%s\n",
			ls,
			mib(bd.PDFTBytes),
			mib(bd.PDFTInvBytes),
			mib(bd.PermuteIdxBytes),
			mib(bd.CtxPoolBytes),
			mib(bd.SineEvalBytes),
			mib(bd.ArcSineBytes),
			mib(bd.Total()),
			bd.NumPDFTMatrices,
			bd.NumPDFTInvMatrix,
			buildElapsed.Round(time.Millisecond))

		totals.PDFTBytes += bd.PDFTBytes
		totals.PDFTInvBytes += bd.PDFTInvBytes
		totals.PermuteIdxBytes += bd.PermuteIdxBytes
		totals.CtxPoolBytes += bd.CtxPoolBytes
		totals.SineEvalBytes += bd.SineEvalBytes
		totals.ArcSineBytes += bd.ArcSineBytes

		phases := btp.RotationsByPhase()
		fmt.Printf("           phase keys  subSum=%d  CtoS=%d  StoC=%d  (max=%d)\n",
			len(phases.SubSum), len(phases.CtoS), len(phases.StoC),
			max3(len(phases.SubSum), len(phases.CtoS), len(phases.StoC)))
		addAll(unionSubSum, phases.SubSum)
		addAll(unionCtoS, phases.CtoS)
		addAll(unionStoC, phases.StoC)
	}

	fmt.Println()
	fmt.Println("=== Aggregate across 5 bootstrappers ===")
	fmt.Printf("  pDFT (StoC matrices):      %8.1f MiB\n", mib(totals.PDFTBytes))
	fmt.Printf("  pDFTInv (CtoS matrices):   %8.1f MiB\n", mib(totals.PDFTInvBytes))
	fmt.Printf("  Permute NTT index tables:  %8.1f MiB\n", mib(totals.PermuteIdxBytes))
	fmt.Printf("  ctxpool ciphertext:        %8.1f MiB\n", mib(totals.CtxPoolBytes))
	fmt.Printf("  Sine Chebyshev coeffs:     %8.1f MiB\n", mib(totals.SineEvalBytes))
	fmt.Printf("  ArcSine Taylor coeffs:     %8.1f MiB\n", mib(totals.ArcSineBytes))
	fmt.Printf("  ----------------------------------------\n")
	fmt.Printf("  TOTAL:                     %8.1f MiB (%.2f GiB)\n",
		mib(totals.Total()), mib(totals.Total())/1024)
	fmt.Println()
	fmt.Println("=== Per-phase boot rotation keys (deduped across all 5 btps) ===")
	mibPerKey := 198.0 // ~198 MiB per boot key, from sweep results metadata
	fmt.Printf("  SubSum:           %3d keys  ≈ %5.1f GiB\n",
		len(unionSubSum), float64(len(unionSubSum))*mibPerKey/1024)
	fmt.Printf("  CoeffsToSlots:    %3d keys  ≈ %5.1f GiB\n",
		len(unionCtoS), float64(len(unionCtoS))*mibPerKey/1024)
	fmt.Printf("  SlotsToCoeffs:    %3d keys  ≈ %5.1f GiB\n",
		len(unionStoC), float64(len(unionStoC))*mibPerKey/1024)
	maxPhase := len(unionSubSum)
	if len(unionCtoS) > maxPhase {
		maxPhase = len(unionCtoS)
	}
	if len(unionStoC) > maxPhase {
		maxPhase = len(unionStoC)
	}
	fmt.Printf("  ----------------------------------------\n")
	fmt.Printf("  Peak phase keys:  %3d keys  ≈ %5.1f GiB  (sub-bootstrap upper bound)\n",
		maxPhase, float64(maxPhase)*mibPerKey/1024)

	fmt.Println()
	fmt.Println("Note: this is the per-bootstrapper precompute that today persists")
	fmt.Println("for the lifetime of the bootstrapper, regardless of paging.")
}

func max3(a, b, c int) int {
	m := a
	if b > m {
		m = b
	}
	if c > m {
		m = c
	}
	return m
}
