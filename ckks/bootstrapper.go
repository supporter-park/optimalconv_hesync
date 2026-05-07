package ckks

import (
	"fmt"
	"math"
	"math/cmplx"

	"github.com/supporter-park/optimalconv_hesync/ckks/bettersine"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/supporter-park/optimalconv_hesync/utils"
)

// Bootstrapper is a struct to stores a memory pool the plaintext matrices
// the polynomial approximation and the keys for the bootstrapping.
type Bootstrapper struct {
	*evaluator
	BootstrappingParameters
	*BootstrappingKey
	params Parameters

	dslots    int // Number of plaintext slots after the re-encoding
	logdslots int

	encoder Encoder // Encoder

	prescale     float64                 // Q[0]/(Q[0]/|m|)
	postscale    float64                 // Qi sineeval/(Q[0]/|m|)
	sinescale    float64                 // Qi sineeval
	sqrt2pi      float64                 // (1/2pi)^{-2^r}
	scFac        float64                 // 2^{r}
	sineEvalPoly *ChebyshevInterpolation // Coefficients of the Chebyshev Interpolation of sin(2*pi*x) or cos(2*pi*x/r)
	arcSinePoly  *Poly                   // Coefficients of the Taylor series of arcsine(x)

	coeffsToSlotsDiffScale complex128      // Matrice rescaling
	slotsToCoeffsDiffScale complex128      // Matrice rescaling
	pDFT                   []*PtDiagMatrix // Matrice vectors
	pDFTInv                []*PtDiagMatrix // Matrice vectors

	rotKeyIndex []int // a list of the required rotation keys
}

func sin2pi2pi(x complex128) complex128 {
	return cmplx.Sin(6.283185307179586*x) / 6.283185307179586
}

func cos2pi(x complex128) complex128 {
	return cmplx.Cos(6.283185307179586 * x)
}

// NewBootstrapper creates a new Bootstrapper.
func NewBootstrapper(params Parameters, btpParams *BootstrappingParameters, btpKey BootstrappingKey) (btp *Bootstrapper, err error) {

	if btpParams.SinType == SinType(Sin) && btpParams.SinRescal != 0 {
		return nil, fmt.Errorf("cannot use double angle formul for SinType = Sin -> must use SinType = Cos")
	}

	btp = newBootstrapper(params, btpParams)

	btp.BootstrappingKey = &BootstrappingKey{btpKey.Rlk, btpKey.Rtks}
	if err = btp.CheckKeys(); err != nil {
		return nil, fmt.Errorf("invalid bootstrapping key: %w", err)
	}
	btp.evaluator = btp.evaluator.WithKey(rlwe.EvaluationKey{Rlk: btpKey.Rlk, Rtks: btpKey.Rtks}).(*evaluator)

	return btp, nil
}

// NewBootstrapper creates a new Bootstrapper.
// modified by DWKIM to set coefficients multiplied on StoC matrices to be 1.0
func NewBootstrapper_mod(params Parameters, btpParams *BootstrappingParameters, btpKey BootstrappingKey) (btp *Bootstrapper, err error) {

	if btpParams.SinType == SinType(Sin) && btpParams.SinRescal != 0 {
		return nil, fmt.Errorf("cannot use double angle formul for SinType = Sin -> must use SinType = Cos")
	}

	btp = newBootstrapper(params, btpParams)
	btp.pDFT = btp.BootstrappingParameters.GenSlotsToCoeffsMatrix(1.0, btp.encoder)

	btp.BootstrappingKey = &BootstrappingKey{btpKey.Rlk, btpKey.Rtks}
	if err = btp.CheckKeys(); err != nil {
		return nil, fmt.Errorf("invalid bootstrapping key: %w", err)
	}
	btp.evaluator = btp.evaluator.WithKey(rlwe.EvaluationKey{Rlk: btpKey.Rlk, Rtks: btpKey.Rtks}).(*evaluator)

	return btp, nil
}

// newBootstrapper is a constructor of "dummy" bootstrapper to enable the generation of bootstrapping-related constants
// without providing a bootstrapping key. To be replaced by a proper factorization of the bootstrapping pre-computations.
func newBootstrapper(params Parameters, btpParams *BootstrappingParameters) (btp *Bootstrapper) {
	btp = new(Bootstrapper)

	btp.params = params
	btp.BootstrappingParameters = *btpParams.Copy()

	btp.dslots = params.Slots()
	btp.logdslots = params.LogSlots()
	if params.LogSlots() < params.MaxLogSlots() {
		btp.dslots <<= 1
		btp.logdslots++
	}

	btp.prescale = math.Exp2(math.Round(math.Log2(float64(params.Q()[0]) / btp.MessageRatio)))
	btp.sinescale = math.Exp2(math.Round(math.Log2(btp.SineEvalModuli.ScalingFactor)))
	btp.postscale = btp.sinescale / btp.MessageRatio

	btp.encoder = NewEncoder(params)
	btp.evaluator = NewEvaluator(params, rlwe.EvaluationKey{}).(*evaluator) // creates an evaluator without keys for genDFTMatrices

	btp.genSinePoly()
	btp.genDFTMatrices()

	btp.ctxpool = NewCiphertext(params, 1, params.MaxLevel(), 0)

	return btp
}

// SetKeys swaps the bootstrapping keys used by an existing Bootstrapper.
// This enables HESync to page bootstrap rotation keys in/out of memory
// without reconstructing the (expensive) precomputed DFT matrices and
// sine polynomial.
//
// The caller is responsible for ensuring btpKey contains all rotation keys
// required by this bootstrapper; CheckKeys is invoked to verify.
func (btp *Bootstrapper) SetKeys(btpKey BootstrappingKey) error {
	btp.BootstrappingKey = &BootstrappingKey{btpKey.Rlk, btpKey.Rtks}
	if err := btp.CheckKeys(); err != nil {
		return err
	}
	btp.evaluator = btp.evaluator.WithKey(rlwe.EvaluationKey{Rlk: btpKey.Rlk, Rtks: btpKey.Rtks}).(*evaluator)
	return nil
}

// PreparePermuteNTTIndex precomputes NTT permutation indexes on the
// bootstrapper's internal evaluator for the given Galois elements. Combined
// with SetKeys, this allows the bootstrapper to run against an rtks whose
// SwitchingKeys are loaded lazily from disk.
func (btp *Bootstrapper) PreparePermuteNTTIndex(galEls []uint64) {
	btp.evaluator.PreparePermuteNTTIndex(galEls)
}

// RotKeyIndex returns the internal rotations (by column shift amount) that
// this bootstrapper requires. The corresponding Galois elements can be
// derived via params.GaloisElementForColumnRotationBy.
func (btp *Bootstrapper) RotKeyIndex() []int {
	out := make([]int, len(btp.rotKeyIndex))
	copy(out, btp.rotKeyIndex)
	return out
}

// CheckKeys checks if all the necessary keys are present
func (btp *Bootstrapper) CheckKeys() (err error) {

	if btp.Rlk == nil {
		return fmt.Errorf("relinearization key is nil")
	}

	if btp.Rtks == nil {
		return fmt.Errorf("rotation key is nil")
	}

	rotMissing := []int{}
	for _, i := range btp.rotKeyIndex {
		galEl := btp.params.GaloisElementForColumnRotationBy(int(i))
		if _, generated := btp.Rtks.Keys[galEl]; !generated {
			rotMissing = append(rotMissing, i)
		}
	}

	if len(rotMissing) != 0 {
		return fmt.Errorf("rotation key(s) missing: %d", rotMissing)
	}

	return nil
}

// NewPrecomputeOnlyBootstrapper builds a Bootstrapper with pDFT/pDFTInv,
// sine polynomials, and the ctxpool fully populated, but with no
// BootstrappingKey attached. Used for measuring precompute footprint
// without paying for key generation. The returned bootstrapper cannot
// run Bootstrapp until SetKeys is called.
func NewPrecomputeOnlyBootstrapper(params Parameters, btpParams *BootstrappingParameters) *Bootstrapper {
	btp := newBootstrapper(params, btpParams)
	// Mirror NewBootstrapper_mod: regenerate StoC matrices with scale 1.0.
	btp.pDFT = btp.BootstrappingParameters.GenSlotsToCoeffsMatrix(1.0, btp.encoder)
	return btp
}

// PrecomputeBreakdown reports the byte size of each precomputed component
// held by a Bootstrapper. All values are in bytes.
type PrecomputeBreakdown struct {
	PDFTBytes        int64 // SlotsToCoeffs matrices
	PDFTInvBytes     int64 // CoeffsToSlots matrices
	SineEvalBytes    int64 // Chebyshev coeffs for sin(2πx)
	ArcSineBytes     int64 // Taylor coeffs for arcsin(x)
	CtxPoolBytes     int64 // ciphertext memory pool
	PermuteIdxBytes  int64 // evaluator's PermuteNTTIndex tables
	NumPDFTMatrices  int   // count of *PtDiagMatrix in pDFT
	NumPDFTInvMatrix int   // count of *PtDiagMatrix in pDFTInv
}

func (b PrecomputeBreakdown) Total() int64 {
	return b.PDFTBytes + b.PDFTInvBytes + b.SineEvalBytes + b.ArcSineBytes + b.CtxPoolBytes + b.PermuteIdxBytes
}

// PrecomputeBreakdown returns a per-component byte breakdown of all
// precomputed data carried by the Bootstrapper. Excludes evaluation keys
// (Rlk, Rtks) — those live on btp.BootstrappingKey, which the paged
// bootstrapper already swaps in/out.
func (btp *Bootstrapper) PrecomputeBreakdown() PrecomputeBreakdown {
	var bd PrecomputeBreakdown
	for _, m := range btp.pDFT {
		bd.PDFTBytes += ptDiagMatrixBytes(m)
	}
	for _, m := range btp.pDFTInv {
		bd.PDFTInvBytes += ptDiagMatrixBytes(m)
	}
	bd.NumPDFTMatrices = len(btp.pDFT)
	bd.NumPDFTInvMatrix = len(btp.pDFTInv)
	if btp.sineEvalPoly != nil {
		bd.SineEvalBytes = int64(len(btp.sineEvalPoly.coeffs)) * 16 // complex128
	}
	if btp.arcSinePoly != nil {
		bd.ArcSineBytes = int64(len(btp.arcSinePoly.coeffs)) * 16
	}
	if btp.ctxpool != nil {
		for _, p := range btp.ctxpool.Value {
			for _, c := range p.Coeffs {
				bd.CtxPoolBytes += int64(len(c)) * 8
			}
		}
	}
	if btp.evaluator != nil {
		for _, idx := range btp.evaluator.permuteNTTIndex {
			bd.PermuteIdxBytes += int64(len(idx)) * 8
		}
	}
	return bd
}

// PerPhaseRotations returns the column-rotation indices required by each
// of the four bootstrapping phases. Galois elements can be derived via
// params.GaloisElementForColumnRotationBy on each entry. EvalSine uses
// only the row-rotation (conjugation) Galois element, which is not
// included here.
type PerPhaseRotations struct {
	SubSum []int
	CtoS   []int
	StoC   []int
}

// RotationsByPhase computes per-phase rotation index sets for this
// bootstrapper. Useful for sizing sub-bootstrap key paging.
func (btp *Bootstrapper) RotationsByPhase() PerPhaseRotations {
	var r PerPhaseRotations
	for i := btp.params.LogSlots(); i < btp.params.MaxLogSlots(); i++ {
		r.SubSum = append(r.SubSum, 1<<i)
	}
	for _, pVec := range btp.pDFTInv {
		r.CtoS = AddMatrixRotToList(pVec, r.CtoS, btp.params.Slots(), false)
	}
	for i, pVec := range btp.pDFT {
		r.StoC = AddMatrixRotToList(pVec, r.StoC, btp.params.Slots(),
			(i == 0) && (btp.params.LogSlots() < btp.params.MaxLogSlots()))
	}
	return r
}

func ptDiagMatrixBytes(m *PtDiagMatrix) int64 {
	if m == nil {
		return 0
	}
	var total int64
	for _, pair := range m.Vec {
		for _, p := range pair {
			if p == nil {
				continue
			}
			for _, row := range p.Coeffs {
				total += int64(len(row)) * 8
			}
		}
	}
	return total
}

// AddMatrixRotToList adds the rotations neede to evaluate pVec to the list rotations
func AddMatrixRotToList(pVec *PtDiagMatrix, rotations []int, slots int, repack bool) []int {

	if pVec.naive {
		for j := range pVec.Vec {
			if !utils.IsInSliceInt(j, rotations) {
				rotations = append(rotations, j)
			}
		}
	} else {
		var index int
		for j := range pVec.Vec {

			N1 := pVec.N1

			index = ((j / N1) * N1)

			if repack {
				// Sparse repacking, occurring during the first DFT matrix of the CoeffsToSlots.
				index &= 2*slots - 1
			} else {
				// Other cases
				index &= slots - 1
			}

			if index != 0 && !utils.IsInSliceInt(index, rotations) {
				rotations = append(rotations, index)
			}

			index = j & (N1 - 1)

			if index != 0 && !utils.IsInSliceInt(index, rotations) {
				rotations = append(rotations, index)
			}
		}
	}

	return rotations
}

func (btp *Bootstrapper) genDFTMatrices() {

	a := real(btp.sineEvalPoly.a)
	b := real(btp.sineEvalPoly.b)
	n := float64(btp.params.N())
	qDiff := float64(btp.params.Q()[0]) / math.Exp2(math.Round(math.Log2(float64(btp.params.Q()[0]))))

	// Change of variable for the evaluation of the Chebyshev polynomial + cancelling factor for the DFT and SubSum + evantual scaling factor for the double angle formula
	btp.coeffsToSlotsDiffScale = complex(math.Pow(2.0/((b-a)*n*btp.scFac*qDiff), 1.0/float64(btp.CtSDepth(false))), 0)

	// Rescaling factor to set the final ciphertext to the desired scale
	btp.slotsToCoeffsDiffScale = complex(math.Pow((qDiff*btp.params.Scale())/btp.postscale, 1.0/float64(btp.StCDepth(false))), 0)

	// CoeffsToSlots vectors
	btp.pDFTInv = btp.BootstrappingParameters.GenCoeffsToSlotsMatrix(btp.coeffsToSlotsDiffScale, btp.encoder)

	// SlotsToCoeffs vectors
	btp.pDFT = btp.BootstrappingParameters.GenSlotsToCoeffsMatrix(btp.slotsToCoeffsDiffScale, btp.encoder)

	// List of the rotation key values to needed for the bootstrapp
	btp.rotKeyIndex = []int{}

	//SubSum rotation needed X -> Y^slots rotations
	for i := btp.params.LogSlots(); i < btp.params.MaxLogSlots(); i++ {
		if !utils.IsInSliceInt(1<<i, btp.rotKeyIndex) {
			btp.rotKeyIndex = append(btp.rotKeyIndex, 1<<i)
		}
	}

	// Coeffs to Slots rotations
	for _, pVec := range btp.pDFTInv {
		btp.rotKeyIndex = AddMatrixRotToList(pVec, btp.rotKeyIndex, btp.params.Slots(), false)
	}

	// Slots to Coeffs rotations
	for i, pVec := range btp.pDFT {
		btp.rotKeyIndex = AddMatrixRotToList(pVec, btp.rotKeyIndex, btp.params.Slots(), (i == 0) && (btp.params.LogSlots() < btp.params.MaxLogSlots()))
	}
}

func (btp *Bootstrapper) genSinePoly() {

	K := int(btp.SinRange)
	deg := int(btp.SinDeg)
	btp.scFac = float64(int(1 << btp.SinRescal))

	if btp.ArcSineDeg > 0 {
		btp.sqrt2pi = 1.0

		coeffs := make([]complex128, btp.ArcSineDeg+1)

		coeffs[1] = 0.15915494309189535

		for i := 3; i < btp.ArcSineDeg+1; i += 2 {

			coeffs[i] = coeffs[i-2] * complex(float64(i*i-4*i+4)/float64(i*i-i), 0)

		}

		btp.arcSinePoly = NewPoly(coeffs)

	} else {
		btp.sqrt2pi = math.Pow(0.15915494309189535, 1.0/btp.scFac)
	}

	if btp.SinType == Sin {

		btp.sineEvalPoly = Approximate(sin2pi2pi, -complex(float64(K)/btp.scFac, 0), complex(float64(K)/btp.scFac, 0), deg)

	} else if btp.SinType == Cos1 {

		btp.sineEvalPoly = new(ChebyshevInterpolation)

		btp.sineEvalPoly.coeffs = bettersine.Approximate(K, deg, btp.MessageRatio, int(btp.SinRescal))

		btp.sineEvalPoly.maxDeg = btp.sineEvalPoly.Degree()
		btp.sineEvalPoly.a = complex(float64(-K)/btp.scFac, 0)
		btp.sineEvalPoly.b = complex(float64(K)/btp.scFac, 0)
		btp.sineEvalPoly.lead = true

	} else if btp.SinType == Cos2 {

		btp.sineEvalPoly = Approximate(cos2pi, -complex(float64(K)/btp.scFac, 0), complex(float64(K)/btp.scFac, 0), deg)

	} else {
		panic("Bootstrapper -> invalid sineType")
	}

	for i := range btp.sineEvalPoly.coeffs {
		btp.sineEvalPoly.coeffs[i] *= complex(btp.sqrt2pi, 0)
	}
}
