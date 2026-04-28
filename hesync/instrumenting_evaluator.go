package hesync

import (
	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/ring"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/supporter-park/optimalconv_hesync/utils"
)

// InstrumentingEvaluator wraps a real ckks.Evaluator and records a Trace of
// every operation as it flows through. Unlike TracingEvaluator (which builds
// fake ciphertexts), this one lets the inner real evaluator actually compute,
// and only attaches metadata bookkeeping on the side.
//
// This is what the benchmark should use when the workload includes operations
// (like bootstrapping) whose outputs cannot be faked accurately — the real
// execution produces correct ciphertexts while the trace captures the same
// EVK/level information that TracingEvaluator would.
type InstrumentingEvaluator struct {
	inner     ckks.Evaluator
	params    ckks.Parameters
	trace     *Trace
	opCounter int
}

// NewInstrumentingEvaluator constructs a new instrumenting evaluator that
// delegates all operations to inner and records them in an internal Trace.
func NewInstrumentingEvaluator(inner ckks.Evaluator, params ckks.Parameters) *InstrumentingEvaluator {
	return &InstrumentingEvaluator{
		inner:  inner,
		params: params,
		trace: &Trace{
			MaxLevel: params.MaxLevel(),
		},
	}
}

// GetTrace returns the accumulated trace.
func (e *InstrumentingEvaluator) GetTrace() *Trace { return e.trace }

func (e *InstrumentingEvaluator) record(op string, inLvl, outLvl int, evks []EVKIdentifier) {
	e.trace.Entries = append(e.trace.Entries, TraceEntry{
		OpIndex:     e.opCounter,
		OpType:      op,
		InputLevel:  inLvl,
		OutputLevel: outLvl,
		EVKs:        evks,
	})
	e.opCounter++
}

func (e *InstrumentingEvaluator) relinEVK() []EVKIdentifier {
	return []EVKIdentifier{{Type: RelinKey, GaloisEl: 0}}
}

func (e *InstrumentingEvaluator) rotEVK(galEl uint64) []EVKIdentifier {
	return []EVKIdentifier{{Type: RotationKey, GaloisEl: galEl}}
}

func (e *InstrumentingEvaluator) rotEVKsFromMatrix(matrix *ckks.PtDiagMatrix) []EVKIdentifier {
	var evks []EVKIdentifier
	seen := make(map[uint64]bool)
	for k := range matrix.Vec {
		if k == 0 {
			continue
		}
		galEl := e.params.GaloisElementForColumnRotationBy(int(k))
		if !seen[galEl] {
			evks = append(evks, EVKIdentifier{Type: RotationKey, GaloisEl: galEl})
			seen[galEl] = true
		}
	}
	return evks
}

// ========================
// Basic Arithmetic
// ========================

func (e *InstrumentingEvaluator) Add(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	e.inner.Add(op0, op1, ctOut)
	e.record("Add", outLevel(op0, op1), ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) AddNoMod(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	e.inner.AddNoMod(op0, op1, ctOut)
	e.record("Add", outLevel(op0, op1), ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) AddNew(op0, op1 ckks.Operand) *ckks.Ciphertext {
	out := e.inner.AddNew(op0, op1)
	e.record("Add", outLevel(op0, op1), out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) AddNoModNew(op0, op1 ckks.Operand) *ckks.Ciphertext {
	out := e.inner.AddNoModNew(op0, op1)
	e.record("Add", outLevel(op0, op1), out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) Sub(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	e.inner.Sub(op0, op1, ctOut)
	e.record("Sub", outLevel(op0, op1), ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) SubNoMod(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	e.inner.SubNoMod(op0, op1, ctOut)
	e.record("Sub", outLevel(op0, op1), ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) SubNew(op0, op1 ckks.Operand) *ckks.Ciphertext {
	out := e.inner.SubNew(op0, op1)
	e.record("Sub", outLevel(op0, op1), out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) SubNoModNew(op0, op1 ckks.Operand) *ckks.Ciphertext {
	out := e.inner.SubNoModNew(op0, op1)
	e.record("Sub", outLevel(op0, op1), out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) Neg(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.Neg(ctIn, ctOut)
	e.record("Neg", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) NegNew(ctIn *ckks.Ciphertext) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.NegNew(ctIn)
	e.record("Neg", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) AddConstNew(ctIn *ckks.Ciphertext, c interface{}) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.AddConstNew(ctIn, c)
	e.record("AddConst", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) AddConst(ctIn *ckks.Ciphertext, c interface{}, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.AddConst(ctIn, c, ctOut)
	e.record("AddConst", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) MultByConstNew(ctIn *ckks.Ciphertext, c interface{}) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.MultByConstNew(ctIn, c)
	e.record("MultByConst", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) MultByConst(ctIn *ckks.Ciphertext, c interface{}, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.MultByConst(ctIn, c, ctOut)
	e.record("MultByConst", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) MultByGaussianInteger(ctIn *ckks.Ciphertext, cReal, cImag int64, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.MultByGaussianInteger(ctIn, cReal, cImag, ctOut)
	e.record("MultByGaussianInteger", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) MultByConstAndAdd(ctIn *ckks.Ciphertext, c interface{}, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.MultByConstAndAdd(ctIn, c, ctOut)
	e.record("MultByConstAndAdd", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) MultByGaussianIntegerAndAdd(ctIn *ckks.Ciphertext, cReal, cImag int64, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.MultByGaussianIntegerAndAdd(ctIn, cReal, cImag, ctOut)
	e.record("MultByGaussianIntegerAndAdd", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) MultByiNew(ctIn *ckks.Ciphertext) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.MultByiNew(ctIn)
	e.record("MultByi", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) MultByi(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.MultByi(ctIn, ctOut)
	e.record("MultByi", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) DivByiNew(ctIn *ckks.Ciphertext) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.DivByiNew(ctIn)
	e.record("DivByi", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) DivByi(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.DivByi(ctIn, ctOut)
	e.record("DivByi", inLvl, ctOut.Level(), nil)
}

// ========================
// Conjugation
// ========================

func (e *InstrumentingEvaluator) ConjugateNew(ctIn *ckks.Ciphertext) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.ConjugateNew(ctIn)
	galEl := e.params.GaloisElementForRowRotation()
	e.record("Conjugate", inLvl, out.Level(), e.rotEVK(galEl))
	return out
}
func (e *InstrumentingEvaluator) Conjugate(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.Conjugate(ctIn, ctOut)
	galEl := e.params.GaloisElementForRowRotation()
	e.record("Conjugate", inLvl, ctOut.Level(), e.rotEVK(galEl))
}

// ========================
// Multiplication
// ========================

func (e *InstrumentingEvaluator) Mul(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	inLvl := outLevel(op0, op1)
	e.inner.Mul(op0, op1, ctOut)
	e.record("Mul", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) MulNew(op0, op1 ckks.Operand) *ckks.Ciphertext {
	inLvl := outLevel(op0, op1)
	out := e.inner.MulNew(op0, op1)
	e.record("Mul", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) MulRelin(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	inLvl := outLevel(op0, op1)
	var evks []EVKIdentifier
	if op0.Degree()+op1.Degree() == 2 {
		evks = e.relinEVK()
	}
	e.inner.MulRelin(op0, op1, ctOut)
	e.record("MulRelin", inLvl, ctOut.Level(), evks)
}
func (e *InstrumentingEvaluator) MulRelinNew(op0, op1 ckks.Operand) *ckks.Ciphertext {
	inLvl := outLevel(op0, op1)
	var evks []EVKIdentifier
	if op0.Degree()+op1.Degree() == 2 {
		evks = e.relinEVK()
	}
	out := e.inner.MulRelinNew(op0, op1)
	e.record("MulRelin", inLvl, out.Level(), evks)
	return out
}

// ========================
// Rotations
// ========================

func (e *InstrumentingEvaluator) RotateNew(ctIn *ckks.Ciphertext, k int) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.RotateNew(ctIn, k)
	var evks []EVKIdentifier
	if k != 0 {
		evks = e.rotEVK(e.params.GaloisElementForColumnRotationBy(k))
	}
	e.record("Rotate", inLvl, out.Level(), evks)
	return out
}
func (e *InstrumentingEvaluator) Rotate(ctIn *ckks.Ciphertext, k int, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.Rotate(ctIn, k, ctOut)
	var evks []EVKIdentifier
	if k != 0 {
		evks = e.rotEVK(e.params.GaloisElementForColumnRotationBy(k))
	}
	e.record("Rotate", inLvl, ctOut.Level(), evks)
}
func (e *InstrumentingEvaluator) RotateGal(ctIn *ckks.Ciphertext, galEl uint64, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.RotateGal(ctIn, galEl, ctOut)
	var evks []EVKIdentifier
	if galEl != 0 {
		evks = e.rotEVK(galEl)
	}
	e.record("RotateGal", inLvl, ctOut.Level(), evks)
}
func (e *InstrumentingEvaluator) RotateHoisted(ctIn *ckks.Ciphertext, rotations []int) map[int]*ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.RotateHoisted(ctIn, rotations)
	var evks []EVKIdentifier
	for _, k := range rotations {
		if k != 0 {
			evks = append(evks, EVKIdentifier{Type: RotationKey, GaloisEl: e.params.GaloisElementForColumnRotationBy(k)})
		}
	}
	e.record("RotateHoisted", inLvl, inLvl, evks)
	return out
}

// ========================
// Advanced Arithmetic
// ========================

func (e *InstrumentingEvaluator) MulByPow2New(ctIn *ckks.Ciphertext, pow2 int) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.MulByPow2New(ctIn, pow2)
	e.record("MulByPow2", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) MulByPow2(ctIn *ckks.Ciphertext, pow2 int, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.MulByPow2(ctIn, pow2, ctOut)
	e.record("MulByPow2", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) PowerOf2(ctIn *ckks.Ciphertext, logPow2 int, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.PowerOf2(ctIn, logPow2, ctOut)
	e.record("PowerOf2", inLvl, ctOut.Level(), e.relinEVK())
}
func (e *InstrumentingEvaluator) Power(ctIn *ckks.Ciphertext, degree int, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.Power(ctIn, degree, ctOut)
	e.record("Power", inLvl, ctOut.Level(), e.relinEVK())
}
func (e *InstrumentingEvaluator) PowerNew(ctIn *ckks.Ciphertext, degree int) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.PowerNew(ctIn, degree)
	e.record("Power", inLvl, out.Level(), e.relinEVK())
	return out
}
func (e *InstrumentingEvaluator) EvaluatePoly(ctIn *ckks.Ciphertext, coeffs *ckks.Poly, targetScale float64) (*ckks.Ciphertext, error) {
	inLvl := ctIn.Level()
	out, err := e.inner.EvaluatePoly(ctIn, coeffs, targetScale)
	outLvl := inLvl
	if out != nil {
		outLvl = out.Level()
	}
	e.record("EvaluatePoly", inLvl, outLvl, e.relinEVK())
	return out, err
}
func (e *InstrumentingEvaluator) EvaluateCheby(ctIn *ckks.Ciphertext, cheby *ckks.ChebyshevInterpolation, targetScale float64) (*ckks.Ciphertext, error) {
	inLvl := ctIn.Level()
	out, err := e.inner.EvaluateCheby(ctIn, cheby, targetScale)
	outLvl := inLvl
	if out != nil {
		outLvl = out.Level()
	}
	e.record("EvaluateCheby", inLvl, outLvl, e.relinEVK())
	return out, err
}
func (e *InstrumentingEvaluator) InverseNew(ctIn *ckks.Ciphertext, steps int) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.InverseNew(ctIn, steps)
	e.record("Inverse", inLvl, out.Level(), e.relinEVK())
	return out
}

// =============================
// Linear Transformations
// =============================

func (e *InstrumentingEvaluator) LinearTransform(ctIn *ckks.Ciphertext, linearTransform interface{}) []*ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.LinearTransform(ctIn, linearTransform)
	var evks []EVKIdentifier
	switch element := linearTransform.(type) {
	case []*ckks.PtDiagMatrix:
		for _, m := range element {
			evks = append(evks, e.rotEVKsFromMatrix(m)...)
		}
	case *ckks.PtDiagMatrix:
		evks = e.rotEVKsFromMatrix(element)
	}
	outLvl := inLvl
	if len(out) > 0 && out[0] != nil {
		outLvl = out[0].Level()
	}
	e.record("LinearTransform", inLvl, outLvl, evks)
	return out
}
func (e *InstrumentingEvaluator) MultiplyByDiagMatrix(ctIn *ckks.Ciphertext, matrix *ckks.PtDiagMatrix, c2QiQDecomp, c2QiPDecomp []*ring.Poly, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.MultiplyByDiagMatrix(ctIn, matrix, c2QiQDecomp, c2QiPDecomp, ctOut)
	e.record("MultiplyByDiagMatrix", inLvl, ctOut.Level(), e.rotEVKsFromMatrix(matrix))
}
func (e *InstrumentingEvaluator) MultiplyByDiagMatrixBSGS(ctIn *ckks.Ciphertext, matrix *ckks.PtDiagMatrix, c2QiQDecomp, c2QiPDecomp []*ring.Poly, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.MultiplyByDiagMatrixBSGS(ctIn, matrix, c2QiQDecomp, c2QiPDecomp, ctOut)
	e.record("MultiplyByDiagMatrixBSGS", inLvl, ctOut.Level(), e.rotEVKsFromMatrix(matrix))
}
func (e *InstrumentingEvaluator) InnerSumLog(ctIn *ckks.Ciphertext, batchSize, n int, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.InnerSumLog(ctIn, batchSize, n, ctOut)
	var evks []EVKIdentifier
	for i := 1; i < n; i <<= 1 {
		evks = append(evks, EVKIdentifier{Type: RotationKey, GaloisEl: e.params.GaloisElementForColumnRotationBy(i * batchSize)})
	}
	e.record("InnerSumLog", inLvl, ctOut.Level(), evks)
}
func (e *InstrumentingEvaluator) InnerSum(ctIn *ckks.Ciphertext, batchSize, n int, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.InnerSum(ctIn, batchSize, n, ctOut)
	var evks []EVKIdentifier
	for i := 1; i < n; i++ {
		evks = append(evks, EVKIdentifier{Type: RotationKey, GaloisEl: e.params.GaloisElementForColumnRotationBy(i * batchSize)})
	}
	e.record("InnerSum", inLvl, ctOut.Level(), evks)
}
func (e *InstrumentingEvaluator) ReplicateLog(ctIn *ckks.Ciphertext, batchSize, n int, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.ReplicateLog(ctIn, batchSize, n, ctOut)
	e.record("ReplicateLog", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) Replicate(ctIn *ckks.Ciphertext, batchSize, n int, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.Replicate(ctIn, batchSize, n, ctOut)
	e.record("Replicate", inLvl, ctOut.Level(), nil)
}

// =============================
// Ciphertext Management
// =============================

func (e *InstrumentingEvaluator) SwitchKeysNew(ctIn *ckks.Ciphertext, swk *rlwe.SwitchingKey) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.SwitchKeysNew(ctIn, swk)
	e.record("SwitchKeys", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) SwitchKeys(ctIn *ckks.Ciphertext, swk *rlwe.SwitchingKey, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.SwitchKeys(ctIn, swk, ctOut)
	e.record("SwitchKeys", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) RelinearizeNew(ctIn *ckks.Ciphertext) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.RelinearizeNew(ctIn)
	e.record("Relinearize", inLvl, out.Level(), e.relinEVK())
	return out
}
func (e *InstrumentingEvaluator) Relinearize(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.Relinearize(ctIn, ctOut)
	e.record("Relinearize", inLvl, ctOut.Level(), e.relinEVK())
}
func (e *InstrumentingEvaluator) ScaleUpNew(ctIn *ckks.Ciphertext, scale float64) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.ScaleUpNew(ctIn, scale)
	e.record("ScaleUp", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) ScaleUp(ctIn *ckks.Ciphertext, scale float64, ctOut *ckks.Ciphertext) {
	inLvl := ctIn.Level()
	e.inner.ScaleUp(ctIn, scale, ctOut)
	e.record("ScaleUp", inLvl, ctOut.Level(), nil)
}
func (e *InstrumentingEvaluator) SetScale(ctIn *ckks.Ciphertext, scale float64) {
	inLvl := ctIn.Level()
	e.inner.SetScale(ctIn, scale)
	// Must record even though SetScale does no crypto work, so the trace's
	// opIndex sequence stays aligned with HESyncEvaluator.opIndex at runtime
	// (HESyncEvaluator.SetScale wraps with before/after, which increments).
	e.record("SetScale", inLvl, inLvl, nil)
}
func (e *InstrumentingEvaluator) Rescale(ctIn *ckks.Ciphertext, minScale float64, ctOut *ckks.Ciphertext) error {
	inLvl := ctIn.Level()
	err := e.inner.Rescale(ctIn, minScale, ctOut)
	e.record("Rescale", inLvl, ctOut.Level(), nil)
	return err
}
func (e *InstrumentingEvaluator) DropLevelNew(ctIn *ckks.Ciphertext, levels int) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.DropLevelNew(ctIn, levels)
	e.record("DropLevel", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) DropLevel(ctIn *ckks.Ciphertext, levels int) {
	inLvl := ctIn.Level()
	e.inner.DropLevel(ctIn, levels)
	e.record("DropLevel", inLvl, ctIn.Level(), nil)
}
func (e *InstrumentingEvaluator) ReduceNew(ctIn *ckks.Ciphertext) *ckks.Ciphertext {
	inLvl := ctIn.Level()
	out := e.inner.ReduceNew(ctIn)
	e.record("Reduce", inLvl, out.Level(), nil)
	return out
}
func (e *InstrumentingEvaluator) Reduce(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) error {
	inLvl := ctIn.Level()
	err := e.inner.Reduce(ctIn, ctOut)
	e.record("Reduce", inLvl, ctOut.Level(), nil)
	return err
}

// ==============
// Others
// ==============

func (e *InstrumentingEvaluator) ShallowCopy() ckks.Evaluator {
	return &InstrumentingEvaluator{
		inner:     e.inner.ShallowCopy(),
		params:    e.params,
		trace:     e.trace,
		opCounter: e.opCounter,
	}
}
func (e *InstrumentingEvaluator) WithKey(evk rlwe.EvaluationKey) ckks.Evaluator {
	return &InstrumentingEvaluator{
		inner:     e.inner.WithKey(evk),
		params:    e.params,
		trace:     e.trace,
		opCounter: e.opCounter,
	}
}
func (e *InstrumentingEvaluator) PreparePermuteNTTIndex(galEls []uint64) {
	e.inner.PreparePermuteNTTIndex(galEls)
}
func (e *InstrumentingEvaluator) SetRotationKeys(rtks *rlwe.RotationKeySet) {
	e.inner.SetRotationKeys(rtks)
}
func (e *InstrumentingEvaluator) SetRelinearizationKey(rlk *rlwe.RelinearizationKey) {
	e.inner.SetRelinearizationKey(rlk)
}

// Statically assert that InstrumentingEvaluator satisfies ckks.Evaluator.
var _ ckks.Evaluator = (*InstrumentingEvaluator)(nil)

// silence unused-import warnings
var _ = utils.MinInt
