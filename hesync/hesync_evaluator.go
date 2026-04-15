package hesync

import (
	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/ring"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
)

// HESyncEvaluator wraps a real ckks.Evaluator and coordinates EVK
// prefetching via the Prefetcher. It implements ckks.Evaluator.
type HESyncEvaluator struct {
	inner      ckks.Evaluator
	prefetcher *Prefetcher
	opIndex    int
}

// NewHESyncEvaluator creates a new HESync-managed evaluator.
// The inner evaluator's key references must already point to the EVKContainer's
// key sets (via SetRotationKeys / SetRelinearizationKey).
func NewHESyncEvaluator(inner ckks.Evaluator, prefetcher *Prefetcher) *HESyncEvaluator {
	return &HESyncEvaluator{
		inner:      inner,
		prefetcher: prefetcher,
	}
}

// before handles pre-operation synchronization.
func (he *HESyncEvaluator) before() {
	he.prefetcher.HandleInstruction(he.opIndex)
}

// after handles post-operation cleanup and advances the operation counter.
func (he *HESyncEvaluator) after() {
	he.prefetcher.FreeUnneeded(he.opIndex)
	he.opIndex++
}

// OpIndex returns the current operation index.
func (he *HESyncEvaluator) OpIndex() int {
	return he.opIndex
}

// ========================
// === Basic Arithmetic ===
// ========================

func (he *HESyncEvaluator) Add(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.Add(op0, op1, ctOut); he.after()
}
func (he *HESyncEvaluator) AddNoMod(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.AddNoMod(op0, op1, ctOut); he.after()
}
func (he *HESyncEvaluator) AddNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.AddNew(op0, op1); he.after(); return
}
func (he *HESyncEvaluator) AddNoModNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.AddNoModNew(op0, op1); he.after(); return
}
func (he *HESyncEvaluator) Sub(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.Sub(op0, op1, ctOut); he.after()
}
func (he *HESyncEvaluator) SubNoMod(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.SubNoMod(op0, op1, ctOut); he.after()
}
func (he *HESyncEvaluator) SubNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.SubNew(op0, op1); he.after(); return
}
func (he *HESyncEvaluator) SubNoModNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.SubNoModNew(op0, op1); he.after(); return
}
func (he *HESyncEvaluator) Neg(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.Neg(ctIn, ctOut); he.after()
}
func (he *HESyncEvaluator) NegNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.NegNew(ctIn); he.after(); return
}
func (he *HESyncEvaluator) AddConstNew(ctIn *ckks.Ciphertext, constant interface{}) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.AddConstNew(ctIn, constant); he.after(); return
}
func (he *HESyncEvaluator) AddConst(ctIn *ckks.Ciphertext, constant interface{}, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.AddConst(ctIn, constant, ctOut); he.after()
}
func (he *HESyncEvaluator) MultByConstNew(ctIn *ckks.Ciphertext, constant interface{}) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.MultByConstNew(ctIn, constant); he.after(); return
}
func (he *HESyncEvaluator) MultByConst(ctIn *ckks.Ciphertext, constant interface{}, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.MultByConst(ctIn, constant, ctOut); he.after()
}
func (he *HESyncEvaluator) MultByGaussianInteger(ctIn *ckks.Ciphertext, cReal, cImag int64, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.MultByGaussianInteger(ctIn, cReal, cImag, ctOut); he.after()
}
func (he *HESyncEvaluator) MultByConstAndAdd(ctIn *ckks.Ciphertext, constant interface{}, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.MultByConstAndAdd(ctIn, constant, ctOut); he.after()
}
func (he *HESyncEvaluator) MultByGaussianIntegerAndAdd(ctIn *ckks.Ciphertext, cReal, cImag int64, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.MultByGaussianIntegerAndAdd(ctIn, cReal, cImag, ctOut); he.after()
}
func (he *HESyncEvaluator) MultByiNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.MultByiNew(ctIn); he.after(); return
}
func (he *HESyncEvaluator) MultByi(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.MultByi(ctIn, ctOut); he.after()
}
func (he *HESyncEvaluator) DivByiNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.DivByiNew(ctIn); he.after(); return
}
func (he *HESyncEvaluator) DivByi(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.DivByi(ctIn, ctOut); he.after()
}

// ========================
// === Conjugation ===
// ========================

func (he *HESyncEvaluator) ConjugateNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.ConjugateNew(ctIn); he.after(); return
}
func (he *HESyncEvaluator) Conjugate(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.Conjugate(ctIn, ctOut); he.after()
}

// ========================
// === Multiplication ===
// ========================

func (he *HESyncEvaluator) Mul(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.Mul(op0, op1, ctOut); he.after()
}
func (he *HESyncEvaluator) MulNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.MulNew(op0, op1); he.after(); return
}
func (he *HESyncEvaluator) MulRelin(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.MulRelin(op0, op1, ctOut); he.after()
}
func (he *HESyncEvaluator) MulRelinNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.MulRelinNew(op0, op1); he.after(); return
}

// ========================
// === Rotations ===
// ========================

func (he *HESyncEvaluator) RotateNew(ctIn *ckks.Ciphertext, k int) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.RotateNew(ctIn, k); he.after(); return
}
func (he *HESyncEvaluator) Rotate(ctIn *ckks.Ciphertext, k int, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.Rotate(ctIn, k, ctOut); he.after()
}
func (he *HESyncEvaluator) RotateGal(ctIn *ckks.Ciphertext, galEl uint64, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.RotateGal(ctIn, galEl, ctOut); he.after()
}
func (he *HESyncEvaluator) RotateHoisted(ctIn *ckks.Ciphertext, rotations []int) (ctOut map[int]*ckks.Ciphertext) {
	he.before(); ctOut = he.inner.RotateHoisted(ctIn, rotations); he.after(); return
}

// ===========================
// === Advanced Arithmetic ===
// ===========================

func (he *HESyncEvaluator) MulByPow2New(ctIn *ckks.Ciphertext, pow2 int) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.MulByPow2New(ctIn, pow2); he.after(); return
}
func (he *HESyncEvaluator) MulByPow2(ctIn *ckks.Ciphertext, pow2 int, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.MulByPow2(ctIn, pow2, ctOut); he.after()
}
func (he *HESyncEvaluator) PowerOf2(ctIn *ckks.Ciphertext, logPow2 int, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.PowerOf2(ctIn, logPow2, ctOut); he.after()
}
func (he *HESyncEvaluator) Power(ctIn *ckks.Ciphertext, degree int, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.Power(ctIn, degree, ctOut); he.after()
}
func (he *HESyncEvaluator) PowerNew(ctIn *ckks.Ciphertext, degree int) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.PowerNew(ctIn, degree); he.after(); return
}
func (he *HESyncEvaluator) EvaluatePoly(ctIn *ckks.Ciphertext, coeffs *ckks.Poly, targetScale float64) (ctOut *ckks.Ciphertext, err error) {
	he.before(); ctOut, err = he.inner.EvaluatePoly(ctIn, coeffs, targetScale); he.after(); return
}
func (he *HESyncEvaluator) EvaluateCheby(ctIn *ckks.Ciphertext, cheby *ckks.ChebyshevInterpolation, targetScale float64) (ctOut *ckks.Ciphertext, err error) {
	he.before(); ctOut, err = he.inner.EvaluateCheby(ctIn, cheby, targetScale); he.after(); return
}
func (he *HESyncEvaluator) InverseNew(ctIn *ckks.Ciphertext, steps int) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.InverseNew(ctIn, steps); he.after(); return
}

// =============================
// === Linear Transformations ===
// =============================

func (he *HESyncEvaluator) LinearTransform(ctIn *ckks.Ciphertext, linearTransform interface{}) (ctOut []*ckks.Ciphertext) {
	he.before(); ctOut = he.inner.LinearTransform(ctIn, linearTransform); he.after(); return
}
func (he *HESyncEvaluator) MultiplyByDiagMatrix(ctIn *ckks.Ciphertext, matrix *ckks.PtDiagMatrix, c2QiQDecomp, c2QiPDecomp []*ring.Poly, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.MultiplyByDiagMatrix(ctIn, matrix, c2QiQDecomp, c2QiPDecomp, ctOut); he.after()
}
func (he *HESyncEvaluator) MultiplyByDiagMatrixBSGS(ctIn *ckks.Ciphertext, matrix *ckks.PtDiagMatrix, c2QiQDecomp, c2QiPDecomp []*ring.Poly, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.MultiplyByDiagMatrixBSGS(ctIn, matrix, c2QiQDecomp, c2QiPDecomp, ctOut); he.after()
}
func (he *HESyncEvaluator) InnerSumLog(ctIn *ckks.Ciphertext, batch, n int, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.InnerSumLog(ctIn, batch, n, ctOut); he.after()
}
func (he *HESyncEvaluator) InnerSum(ctIn *ckks.Ciphertext, batch, n int, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.InnerSum(ctIn, batch, n, ctOut); he.after()
}
func (he *HESyncEvaluator) ReplicateLog(ctIn *ckks.Ciphertext, batch, n int, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.ReplicateLog(ctIn, batch, n, ctOut); he.after()
}
func (he *HESyncEvaluator) Replicate(ctIn *ckks.Ciphertext, batch, n int, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.Replicate(ctIn, batch, n, ctOut); he.after()
}

// =============================
// === Ciphertext Management ===
// =============================

func (he *HESyncEvaluator) SwitchKeysNew(ctIn *ckks.Ciphertext, switchingKey *rlwe.SwitchingKey) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.SwitchKeysNew(ctIn, switchingKey); he.after(); return
}
func (he *HESyncEvaluator) SwitchKeys(ctIn *ckks.Ciphertext, switchingKey *rlwe.SwitchingKey, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.SwitchKeys(ctIn, switchingKey, ctOut); he.after()
}
func (he *HESyncEvaluator) RelinearizeNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.RelinearizeNew(ctIn); he.after(); return
}
func (he *HESyncEvaluator) Relinearize(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.Relinearize(ctIn, ctOut); he.after()
}
func (he *HESyncEvaluator) ScaleUpNew(ctIn *ckks.Ciphertext, scale float64) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.ScaleUpNew(ctIn, scale); he.after(); return
}
func (he *HESyncEvaluator) ScaleUp(ctIn *ckks.Ciphertext, scale float64, ctOut *ckks.Ciphertext) {
	he.before(); he.inner.ScaleUp(ctIn, scale, ctOut); he.after()
}
func (he *HESyncEvaluator) SetScale(ctIn *ckks.Ciphertext, scale float64) {
	he.before(); he.inner.SetScale(ctIn, scale); he.after()
}
func (he *HESyncEvaluator) Rescale(ctIn *ckks.Ciphertext, minScale float64, ctOut *ckks.Ciphertext) (err error) {
	he.before(); err = he.inner.Rescale(ctIn, minScale, ctOut); he.after(); return
}
func (he *HESyncEvaluator) DropLevelNew(ctIn *ckks.Ciphertext, levels int) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.DropLevelNew(ctIn, levels); he.after(); return
}
func (he *HESyncEvaluator) DropLevel(ctIn *ckks.Ciphertext, levels int) {
	he.before(); he.inner.DropLevel(ctIn, levels); he.after()
}
func (he *HESyncEvaluator) ReduceNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	he.before(); ctOut = he.inner.ReduceNew(ctIn); he.after(); return
}
func (he *HESyncEvaluator) Reduce(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) error {
	he.before(); err := he.inner.Reduce(ctIn, ctOut); he.after(); return err
}

// ==============
// === Others ===
// ==============

func (he *HESyncEvaluator) ShallowCopy() ckks.Evaluator {
	return &HESyncEvaluator{
		inner:      he.inner.ShallowCopy(),
		prefetcher: he.prefetcher,
		opIndex:    he.opIndex,
	}
}

func (he *HESyncEvaluator) WithKey(evk rlwe.EvaluationKey) ckks.Evaluator {
	return &HESyncEvaluator{
		inner:      he.inner.WithKey(evk),
		prefetcher: he.prefetcher,
		opIndex:    he.opIndex,
	}
}

func (he *HESyncEvaluator) PreparePermuteNTTIndex(galEls []uint64) {
	he.inner.PreparePermuteNTTIndex(galEls)
}
func (he *HESyncEvaluator) SetRotationKeys(rtks *rlwe.RotationKeySet) {
	he.inner.SetRotationKeys(rtks)
}
func (he *HESyncEvaluator) SetRelinearizationKey(rlk *rlwe.RelinearizationKey) {
	he.inner.SetRelinearizationKey(rlk)
}
