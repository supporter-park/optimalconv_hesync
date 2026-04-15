package hesync

import (
	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/ring"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/supporter-park/optimalconv_hesync/utils"
)

// TraceEntry records a single HE operation during a dry run.
type TraceEntry struct {
	OpIndex     int             // Position in the trace sequence
	OpType      string          // Operation name (e.g. "MulRelin", "Rotate", "Rescale")
	InputLevel  int             // Ciphertext level before the operation
	OutputLevel int             // Ciphertext level after the operation
	EVKs        []EVKIdentifier // Evaluation keys required (empty for non-EVK ops)
}

// Trace is the complete record of a dry-run execution.
type Trace struct {
	Entries  []TraceEntry
	MaxLevel int
}

// TracingEvaluator implements ckks.Evaluator and records a trace of operations
// without performing actual computation. It tracks ciphertext metadata (level,
// scale, degree) using lightweight ciphertext objects.
type TracingEvaluator struct {
	params    ckks.Parameters
	trace     *Trace
	opCounter int
}

// NewTracingEvaluator creates a new TracingEvaluator for the given parameters.
func NewTracingEvaluator(params ckks.Parameters) *TracingEvaluator {
	return &TracingEvaluator{
		params: params,
		trace: &Trace{
			MaxLevel: params.MaxLevel(),
		},
	}
}

// GetTrace returns the recorded trace.
func (te *TracingEvaluator) GetTrace() *Trace {
	return te.trace
}

// newTracerCiphertext creates a lightweight ciphertext that only has correct
// metadata (Level, Degree, Scale) without allocating polynomial data.
// Level() reads len(Value[0].Coeffs)-1, so we allocate Coeffs with the right
// length but nil inner slices.
func newTracerCiphertext(params ckks.Parameters, degree, level int, scale float64) *ckks.Ciphertext {
	el := &rlwe.Ciphertext{Value: make([]*ring.Poly, degree+1)}
	for i := range el.Value {
		el.Value[i] = &ring.Poly{Coeffs: make([][]uint64, level+1), IsNTT: true}
	}
	return &ckks.Ciphertext{Ciphertext: el, Scale: scale}
}

func (te *TracingEvaluator) record(opType string, inputLevel, outputLevel int, evks []EVKIdentifier) {
	te.trace.Entries = append(te.trace.Entries, TraceEntry{
		OpIndex:     te.opCounter,
		OpType:      opType,
		InputLevel:  inputLevel,
		OutputLevel: outputLevel,
		EVKs:        evks,
	})
	te.opCounter++
}

func (te *TracingEvaluator) relinEVK() []EVKIdentifier {
	return []EVKIdentifier{{Type: RelinKey, GaloisEl: 0}}
}

func (te *TracingEvaluator) rotEVK(galEl uint64) []EVKIdentifier {
	return []EVKIdentifier{{Type: RotationKey, GaloisEl: galEl}}
}

// outLevel returns the output level given two operands (min of their levels).
func outLevel(op0, op1 ckks.Operand) int {
	return utils.MinInt(op0.Level(), op1.Level())
}

// copyMeta sets ctOut metadata to match the given level, degree, scale.
func copyMeta(ctOut *ckks.Ciphertext, level, degree int, scale float64) {
	// Resize the Value slice if needed
	if len(ctOut.Value) != degree+1 {
		ctOut.Value = make([]*ring.Poly, degree+1)
	}
	for i := range ctOut.Value {
		if ctOut.Value[i] == nil {
			ctOut.Value[i] = &ring.Poly{}
		}
		ctOut.Value[i].Coeffs = make([][]uint64, level+1)
		ctOut.Value[i].IsNTT = true
	}
	ctOut.Scale = scale
}

// ========================
// === Basic Arithmetic ===
// ========================

func (te *TracingEvaluator) Add(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	lvl := outLevel(op0, op1)
	te.record("Add", lvl, lvl, nil)
	copyMeta(ctOut, lvl, utils.MaxInt(op0.Degree(), op1.Degree()), op0.ScalingFactor())
}

func (te *TracingEvaluator) AddNoMod(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	lvl := outLevel(op0, op1)
	te.record("Add", lvl, lvl, nil)
	copyMeta(ctOut, lvl, utils.MaxInt(op0.Degree(), op1.Degree()), op0.ScalingFactor())
}

func (te *TracingEvaluator) AddNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	lvl := outLevel(op0, op1)
	ctOut = newTracerCiphertext(te.params, utils.MaxInt(op0.Degree(), op1.Degree()), lvl, op0.ScalingFactor())
	te.record("Add", lvl, lvl, nil)
	return
}

func (te *TracingEvaluator) AddNoModNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	return te.AddNew(op0, op1)
}

func (te *TracingEvaluator) Sub(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	lvl := outLevel(op0, op1)
	te.record("Sub", lvl, lvl, nil)
	copyMeta(ctOut, lvl, utils.MaxInt(op0.Degree(), op1.Degree()), op0.ScalingFactor())
}

func (te *TracingEvaluator) SubNoMod(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	te.Sub(op0, op1, ctOut)
}

func (te *TracingEvaluator) SubNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	lvl := outLevel(op0, op1)
	ctOut = newTracerCiphertext(te.params, utils.MaxInt(op0.Degree(), op1.Degree()), lvl, op0.ScalingFactor())
	te.record("Sub", lvl, lvl, nil)
	return
}

func (te *TracingEvaluator) SubNoModNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	return te.SubNew(op0, op1)
}

func (te *TracingEvaluator) Neg(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("Neg", lvl, lvl, nil)
	copyMeta(ctOut, lvl, ctIn.Degree(), ctIn.Scale)
}

func (te *TracingEvaluator) NegNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale)
	te.record("Neg", ctIn.Level(), ctIn.Level(), nil)
	return
}

func (te *TracingEvaluator) AddConstNew(ctIn *ckks.Ciphertext, constant interface{}) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale)
	te.record("AddConst", ctIn.Level(), ctIn.Level(), nil)
	return
}

func (te *TracingEvaluator) AddConst(ctIn *ckks.Ciphertext, constant interface{}, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("AddConst", lvl, lvl, nil)
	copyMeta(ctOut, lvl, ctIn.Degree(), ctIn.Scale)
}

func (te *TracingEvaluator) MultByConstNew(ctIn *ckks.Ciphertext, constant interface{}) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale)
	te.record("MultByConst", ctIn.Level(), ctIn.Level(), nil)
	return
}

func (te *TracingEvaluator) MultByConst(ctIn *ckks.Ciphertext, constant interface{}, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("MultByConst", lvl, lvl, nil)
	copyMeta(ctOut, lvl, ctIn.Degree(), ctIn.Scale)
}

func (te *TracingEvaluator) MultByGaussianInteger(ctIn *ckks.Ciphertext, cReal, cImag int64, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("MultByGaussianInteger", lvl, lvl, nil)
	copyMeta(ctOut, lvl, ctIn.Degree(), ctIn.Scale)
}

func (te *TracingEvaluator) MultByConstAndAdd(ctIn *ckks.Ciphertext, constant interface{}, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("MultByConstAndAdd", lvl, lvl, nil)
	// ctOut metadata stays the same (accumulator pattern)
}

func (te *TracingEvaluator) MultByGaussianIntegerAndAdd(ctIn *ckks.Ciphertext, cReal, cImag int64, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("MultByGaussianIntegerAndAdd", lvl, lvl, nil)
}

func (te *TracingEvaluator) MultByiNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale)
	te.record("MultByi", ctIn.Level(), ctIn.Level(), nil)
	return
}

func (te *TracingEvaluator) MultByi(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("MultByi", lvl, lvl, nil)
	copyMeta(ctOut, lvl, ctIn.Degree(), ctIn.Scale)
}

func (te *TracingEvaluator) DivByiNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale)
	te.record("DivByi", ctIn.Level(), ctIn.Level(), nil)
	return
}

func (te *TracingEvaluator) DivByi(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("DivByi", lvl, lvl, nil)
	copyMeta(ctOut, lvl, ctIn.Degree(), ctIn.Scale)
}

// ========================
// === Conjugation ===
// ========================

func (te *TracingEvaluator) ConjugateNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	galEl := te.params.GaloisElementForRowRotation()
	ctOut = newTracerCiphertext(te.params, 1, ctIn.Level(), ctIn.Scale)
	te.record("Conjugate", ctIn.Level(), ctIn.Level(), te.rotEVK(galEl))
	return
}

func (te *TracingEvaluator) Conjugate(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	galEl := te.params.GaloisElementForRowRotation()
	lvl := ctIn.Level()
	te.record("Conjugate", lvl, lvl, te.rotEVK(galEl))
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

// ========================
// === Multiplication ===
// ========================

func (te *TracingEvaluator) Mul(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	lvl := outLevel(op0, op1)
	outDeg := op0.Degree() + op1.Degree()
	scale := op0.ScalingFactor() * op1.ScalingFactor()
	te.record("Mul", lvl, lvl, nil)
	copyMeta(ctOut, lvl, outDeg, scale)
}

func (te *TracingEvaluator) MulNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	lvl := outLevel(op0, op1)
	outDeg := op0.Degree() + op1.Degree()
	scale := op0.ScalingFactor() * op1.ScalingFactor()
	ctOut = newTracerCiphertext(te.params, outDeg, lvl, scale)
	te.record("Mul", lvl, lvl, nil)
	return
}

func (te *TracingEvaluator) MulRelin(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	lvl := outLevel(op0, op1)
	scale := op0.ScalingFactor() * op1.ScalingFactor()
	var evks []EVKIdentifier
	// Relin key only used when both operands are degree 1 (ct x ct)
	if op0.Degree()+op1.Degree() == 2 {
		evks = te.relinEVK()
	}
	te.record("MulRelin", lvl, lvl, evks)
	copyMeta(ctOut, lvl, 1, scale)
}

func (te *TracingEvaluator) MulRelinNew(op0, op1 ckks.Operand) (ctOut *ckks.Ciphertext) {
	lvl := outLevel(op0, op1)
	scale := op0.ScalingFactor() * op1.ScalingFactor()
	ctOut = newTracerCiphertext(te.params, 1, lvl, scale)
	var evks []EVKIdentifier
	if op0.Degree()+op1.Degree() == 2 {
		evks = te.relinEVK()
	}
	te.record("MulRelin", lvl, lvl, evks)
	return
}

// ========================
// === Rotations ===
// ========================

func (te *TracingEvaluator) RotateNew(ctIn *ckks.Ciphertext, k int) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, 1, ctIn.Level(), ctIn.Scale)
	if k != 0 {
		galEl := te.params.GaloisElementForColumnRotationBy(k)
		te.record("Rotate", ctIn.Level(), ctIn.Level(), te.rotEVK(galEl))
	} else {
		te.record("Rotate", ctIn.Level(), ctIn.Level(), nil)
	}
	return
}

func (te *TracingEvaluator) Rotate(ctIn *ckks.Ciphertext, k int, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	if k != 0 {
		galEl := te.params.GaloisElementForColumnRotationBy(k)
		te.record("Rotate", lvl, lvl, te.rotEVK(galEl))
	} else {
		te.record("Rotate", lvl, lvl, nil)
	}
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

func (te *TracingEvaluator) RotateGal(ctIn *ckks.Ciphertext, galEl uint64, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	if galEl != 0 {
		te.record("RotateGal", lvl, lvl, te.rotEVK(galEl))
	} else {
		te.record("RotateGal", lvl, lvl, nil)
	}
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

func (te *TracingEvaluator) RotateHoisted(ctIn *ckks.Ciphertext, rotations []int) (ctOut map[int]*ckks.Ciphertext) {
	lvl := ctIn.Level()
	var evks []EVKIdentifier
	for _, k := range rotations {
		if k != 0 {
			galEl := te.params.GaloisElementForColumnRotationBy(k)
			evks = append(evks, EVKIdentifier{Type: RotationKey, GaloisEl: galEl})
		}
	}
	te.record("RotateHoisted", lvl, lvl, evks)

	ctOut = make(map[int]*ckks.Ciphertext, len(rotations))
	for _, k := range rotations {
		ctOut[k] = newTracerCiphertext(te.params, 1, lvl, ctIn.Scale)
	}
	return
}

// ===========================
// === Advanced Arithmetic ===
// ===========================

func (te *TracingEvaluator) MulByPow2New(ctIn *ckks.Ciphertext, pow2 int) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale)
	te.record("MulByPow2", ctIn.Level(), ctIn.Level(), nil)
	return
}

func (te *TracingEvaluator) MulByPow2(ctIn *ckks.Ciphertext, pow2 int, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("MulByPow2", lvl, lvl, nil)
	copyMeta(ctOut, lvl, ctIn.Degree(), ctIn.Scale)
}

func (te *TracingEvaluator) PowerOf2(ctIn *ckks.Ciphertext, logPow2 int, ctOut *ckks.Ciphertext) {
	// PowerOf2 does logPow2 MulRelin + Rescale steps, each consuming one level
	lvl := ctIn.Level()
	scale := ctIn.Scale
	for i := 0; i < logPow2; i++ {
		scale = scale * scale
		te.record("MulRelin", lvl, lvl, te.relinEVK())
		// Rescale consumes one level
		lvl--
		scale = scale / te.params.Scale()
		te.record("Rescale", lvl+1, lvl, nil)
	}
	if logPow2 == 0 {
		te.record("PowerOf2", ctIn.Level(), ctIn.Level(), nil)
	}
	copyMeta(ctOut, lvl, 1, scale)
}

func (te *TracingEvaluator) Power(ctIn *ckks.Ciphertext, degree int, ctOut *ckks.Ciphertext) {
	// Power decomposes into PowerOf2 calls + multiplications
	// For tracing, we approximate the level consumption
	te.PowerOf2(ctIn, 0, ctOut)
	// Simplified: each power step consumes MulRelin + Rescale
	// This is an approximation; the exact decomposition follows bits of degree
	lvl := ctIn.Level()
	outLvl := lvl
	if degree > 1 {
		steps := 0
		d := degree
		for d > 1 {
			d = d >> 1
			steps++
		}
		outLvl = lvl - steps
		if outLvl < 0 {
			outLvl = 0
		}
	}
	copyMeta(ctOut, outLvl, 1, ctIn.Scale)
}

func (te *TracingEvaluator) PowerNew(ctIn *ckks.Ciphertext, degree int) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, 1, ctIn.Level(), ctIn.Scale)
	te.Power(ctIn, degree, ctOut)
	return
}

func (te *TracingEvaluator) EvaluatePoly(ctIn *ckks.Ciphertext, pol *ckks.Poly, targetScale float64) (ctOut *ckks.Ciphertext, err error) {
	// Polynomial evaluation consumes log2(degree) levels via baby-step/giant-step
	deg := pol.Degree()
	levelsConsumed := 0
	d := deg
	for d > 1 {
		d = (d + 1) >> 1
		levelsConsumed++
	}
	outLvl := ctIn.Level() - levelsConsumed
	if outLvl < 0 {
		outLvl = 0
	}
	ctOut = newTracerCiphertext(te.params, 1, outLvl, targetScale)
	te.record("EvaluatePoly", ctIn.Level(), outLvl, te.relinEVK())
	return ctOut, nil
}

func (te *TracingEvaluator) EvaluateCheby(ctIn *ckks.Ciphertext, cheby *ckks.ChebyshevInterpolation, targetScale float64) (ctOut *ckks.Ciphertext, err error) {
	deg := cheby.Degree()
	levelsConsumed := 0
	d := deg
	for d > 1 {
		d = (d + 1) >> 1
		levelsConsumed++
	}
	outLvl := ctIn.Level() - levelsConsumed
	if outLvl < 0 {
		outLvl = 0
	}
	ctOut = newTracerCiphertext(te.params, 1, outLvl, targetScale)
	te.record("EvaluateCheby", ctIn.Level(), outLvl, te.relinEVK())
	return ctOut, nil
}

func (te *TracingEvaluator) InverseNew(ctIn *ckks.Ciphertext, steps int) (ctOut *ckks.Ciphertext) {
	// InverseNew consumes 'steps' levels (each step: MulRelin + Rescale)
	outLvl := ctIn.Level() - steps
	if outLvl < 0 {
		outLvl = 0
	}
	ctOut = newTracerCiphertext(te.params, 1, outLvl, ctIn.Scale)
	te.record("Inverse", ctIn.Level(), outLvl, te.relinEVK())
	return
}

// =============================
// === Linear Transformations ===
// =============================

func (te *TracingEvaluator) LinearTransform(ctIn *ckks.Ciphertext, linearTransform interface{}) (ctOut []*ckks.Ciphertext) {
	lvl := ctIn.Level()

	switch element := linearTransform.(type) {
	case []*ckks.PtDiagMatrix:
		ctOut = make([]*ckks.Ciphertext, len(element))
		var evks []EVKIdentifier
		for i, matrix := range element {
			minLvl := utils.MinInt(matrix.Level, lvl)
			ctOut[i] = newTracerCiphertext(te.params, 1, minLvl, ctIn.Scale)
			// Collect rotation keys from matrix diagonals
			evks = append(evks, te.rotEVKsFromMatrix(matrix)...)
		}
		te.record("LinearTransform", lvl, ctOut[0].Level(), evks)
	case *ckks.PtDiagMatrix:
		minLvl := utils.MinInt(element.Level, lvl)
		ctOut = []*ckks.Ciphertext{newTracerCiphertext(te.params, 1, minLvl, ctIn.Scale)}
		evks := te.rotEVKsFromMatrix(element)
		te.record("LinearTransform", lvl, minLvl, evks)
	}

	return
}

func (te *TracingEvaluator) rotEVKsFromMatrix(matrix *ckks.PtDiagMatrix) []EVKIdentifier {
	// Extract rotation key requirements from a diagonal matrix.
	// Each non-zero diagonal index requires a rotation key.
	var evks []EVKIdentifier
	seen := make(map[uint64]bool)
	for k := range matrix.Vec {
		if k == 0 {
			continue
		}
		galEl := te.params.GaloisElementForColumnRotationBy(int(k))
		if !seen[galEl] {
			evks = append(evks, EVKIdentifier{Type: RotationKey, GaloisEl: galEl})
			seen[galEl] = true
		}
	}
	return evks
}

func (te *TracingEvaluator) MultiplyByDiagMatrix(ctIn *ckks.Ciphertext, matrix *ckks.PtDiagMatrix, c2QiQDecomp, c2QiPDecomp []*ring.Poly, ctOut *ckks.Ciphertext) {
	lvl := utils.MinInt(matrix.Level, ctIn.Level())
	evks := te.rotEVKsFromMatrix(matrix)
	te.record("MultiplyByDiagMatrix", ctIn.Level(), lvl, evks)
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

func (te *TracingEvaluator) MultiplyByDiagMatrixBSGS(ctIn *ckks.Ciphertext, matrix *ckks.PtDiagMatrix, c2QiQDecomp, c2QiPDecomp []*ring.Poly, ctOut *ckks.Ciphertext) {
	lvl := utils.MinInt(matrix.Level, ctIn.Level())
	evks := te.rotEVKsFromMatrix(matrix)
	te.record("MultiplyByDiagMatrixBSGS", ctIn.Level(), lvl, evks)
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

func (te *TracingEvaluator) InnerSumLog(ctIn *ckks.Ciphertext, batchSize, n int, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	var evks []EVKIdentifier
	for i := 1; i < n; i <<= 1 {
		galEl := te.params.GaloisElementForColumnRotationBy(i * batchSize)
		evks = append(evks, EVKIdentifier{Type: RotationKey, GaloisEl: galEl})
	}
	te.record("InnerSumLog", lvl, lvl, evks)
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

func (te *TracingEvaluator) InnerSum(ctIn *ckks.Ciphertext, batchSize, n int, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	var evks []EVKIdentifier
	for i := 1; i < n; i++ {
		galEl := te.params.GaloisElementForColumnRotationBy(i * batchSize)
		evks = append(evks, EVKIdentifier{Type: RotationKey, GaloisEl: galEl})
	}
	te.record("InnerSum", lvl, lvl, evks)
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

func (te *TracingEvaluator) ReplicateLog(ctIn *ckks.Ciphertext, batchSize, n int, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("ReplicateLog", lvl, lvl, nil) // uses rotations internally but simplified
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

func (te *TracingEvaluator) Replicate(ctIn *ckks.Ciphertext, batchSize, n int, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("Replicate", lvl, lvl, nil)
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

// =============================
// === Ciphertext Management ===
// =============================

func (te *TracingEvaluator) SwitchKeysNew(ctIn *ckks.Ciphertext, switchingKey *rlwe.SwitchingKey) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, 1, ctIn.Level(), ctIn.Scale)
	// SwitchKeys uses an explicit key, not from the evaluator's key set
	te.record("SwitchKeys", ctIn.Level(), ctIn.Level(), nil)
	return
}

func (te *TracingEvaluator) SwitchKeys(ctIn *ckks.Ciphertext, switchingKey *rlwe.SwitchingKey, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("SwitchKeys", lvl, lvl, nil)
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

func (te *TracingEvaluator) RelinearizeNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, 1, ctIn.Level(), ctIn.Scale)
	te.record("Relinearize", ctIn.Level(), ctIn.Level(), te.relinEVK())
	return
}

func (te *TracingEvaluator) Relinearize(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("Relinearize", lvl, lvl, te.relinEVK())
	copyMeta(ctOut, lvl, 1, ctIn.Scale)
}

func (te *TracingEvaluator) ScaleUpNew(ctIn *ckks.Ciphertext, scale float64) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale*scale)
	te.record("ScaleUp", ctIn.Level(), ctIn.Level(), nil)
	return
}

func (te *TracingEvaluator) ScaleUp(ctIn *ckks.Ciphertext, scale float64, ctOut *ckks.Ciphertext) {
	lvl := ctIn.Level()
	te.record("ScaleUp", lvl, lvl, nil)
	copyMeta(ctOut, lvl, ctIn.Degree(), ctIn.Scale*scale)
}

func (te *TracingEvaluator) SetScale(ctIn *ckks.Ciphertext, scale float64) {
	ctIn.Scale = scale
	// SetScale is metadata-only, no trace entry needed
}

func (te *TracingEvaluator) Rescale(ctIn *ckks.Ciphertext, minScale float64, ctOut *ckks.Ciphertext) (err error) {
	if ctIn.Level() == 0 {
		return nil
	}
	inLvl := ctIn.Level()
	// Simulate rescaling: divide scale by moduli until minScale/2 is reached
	scale := ctIn.Scale
	nbRescale := 0
	moduli := te.params.Q()
	for scale/float64(moduli[inLvl-nbRescale]) >= minScale/2 && inLvl-nbRescale > 0 {
		scale /= float64(moduli[inLvl-nbRescale])
		nbRescale++
	}
	outLvl := inLvl - nbRescale
	te.record("Rescale", inLvl, outLvl, nil)
	copyMeta(ctOut, outLvl, ctIn.Degree(), scale)
	return nil
}

func (te *TracingEvaluator) DropLevelNew(ctIn *ckks.Ciphertext, levels int) (ctOut *ckks.Ciphertext) {
	outLvl := ctIn.Level() - levels
	if outLvl < 0 {
		outLvl = 0
	}
	ctOut = newTracerCiphertext(te.params, ctIn.Degree(), outLvl, ctIn.Scale)
	te.record("DropLevel", ctIn.Level(), outLvl, nil)
	return
}

func (te *TracingEvaluator) DropLevel(ctIn *ckks.Ciphertext, levels int) {
	inLvl := ctIn.Level()
	outLvl := inLvl - levels
	if outLvl < 0 {
		outLvl = 0
	}
	te.record("DropLevel", inLvl, outLvl, nil)
	// Modify the ciphertext in place (truncate Coeffs like the real evaluator)
	for i := range ctIn.Value {
		ctIn.Value[i].Coeffs = ctIn.Value[i].Coeffs[:outLvl+1]
	}
}

func (te *TracingEvaluator) ReduceNew(ctIn *ckks.Ciphertext) (ctOut *ckks.Ciphertext) {
	ctOut = newTracerCiphertext(te.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale)
	te.record("Reduce", ctIn.Level(), ctIn.Level(), nil)
	return
}

func (te *TracingEvaluator) Reduce(ctIn *ckks.Ciphertext, ctOut *ckks.Ciphertext) error {
	lvl := ctIn.Level()
	te.record("Reduce", lvl, lvl, nil)
	copyMeta(ctOut, lvl, ctIn.Degree(), ctIn.Scale)
	return nil
}

// ==============
// === Others ===
// ==============

func (te *TracingEvaluator) ShallowCopy() ckks.Evaluator {
	return &TracingEvaluator{
		params:    te.params,
		trace:     te.trace,
		opCounter: te.opCounter,
	}
}

func (te *TracingEvaluator) WithKey(evk rlwe.EvaluationKey) ckks.Evaluator {
	return te // keys are not used in tracing
}

func (te *TracingEvaluator) PreparePermuteNTTIndex(galEls []uint64) {}
func (te *TracingEvaluator) SetRotationKeys(rtks *rlwe.RotationKeySet) {}
func (te *TracingEvaluator) SetRelinearizationKey(rlk *rlwe.RelinearizationKey) {}
