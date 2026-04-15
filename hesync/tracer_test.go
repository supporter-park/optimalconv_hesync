package hesync

import (
	"testing"

	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/stretchr/testify/require"
)

// testParams returns CKKS parameters for tracer testing (PN13QP218: logN=13, 6 Q moduli, MaxLevel=5).
func testParams() ckks.Parameters {
	params, err := ckks.NewParametersFromLiteral(ckks.PN13QP218)
	if err != nil {
		panic(err)
	}
	return params
}

func TestTracerBasicArithmetic(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	ct1 := newTracerCiphertext(params, 1, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())

	// Add: level stays the same, no EVKs
	tracer.Add(ct0, ct1, ctOut)
	// Sub: level stays the same, no EVKs
	tracer.Sub(ct0, ct1, ctOut)
	// Neg: level stays the same, no EVKs
	tracer.Neg(ct0, ctOut)

	trace := tracer.GetTrace()
	require.Equal(t, 3, len(trace.Entries))

	for i, entry := range trace.Entries {
		require.Equal(t, i, entry.OpIndex)
		require.Equal(t, 3, entry.InputLevel)
		require.Equal(t, 3, entry.OutputLevel)
		require.Empty(t, entry.EVKs, "basic arithmetic should not require EVKs")
	}
	require.Equal(t, "Add", trace.Entries[0].OpType)
	require.Equal(t, "Sub", trace.Entries[1].OpType)
	require.Equal(t, "Neg", trace.Entries[2].OpType)
}

func TestTracerMulRelin(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	ct1 := newTracerCiphertext(params, 1, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())

	// MulRelin (ct x ct): requires relin key
	tracer.MulRelin(ct0, ct1, ctOut)

	trace := tracer.GetTrace()
	require.Equal(t, 1, len(trace.Entries))

	entry := trace.Entries[0]
	require.Equal(t, "MulRelin", entry.OpType)
	require.Equal(t, 3, entry.InputLevel)
	require.Equal(t, 3, entry.OutputLevel)
	require.Equal(t, 1, len(entry.EVKs))
	require.Equal(t, RelinKey, entry.EVKs[0].Type)
}

func TestTracerMulRelinPlaintext(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	// Degree 0 operand simulates a plaintext
	pt := newTracerCiphertext(params, 0, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())

	// MulRelin (ct x pt): degree sum is 1, no relin key needed
	tracer.MulRelin(ct0, pt, ctOut)

	trace := tracer.GetTrace()
	require.Equal(t, 1, len(trace.Entries))
	require.Empty(t, trace.Entries[0].EVKs, "ct x pt should not need relin key")
}

func TestTracerRotate(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())

	// Rotate by k=5: needs rotation key
	tracer.Rotate(ct0, 5, ctOut)

	trace := tracer.GetTrace()
	require.Equal(t, 1, len(trace.Entries))

	entry := trace.Entries[0]
	require.Equal(t, "Rotate", entry.OpType)
	require.Equal(t, 1, len(entry.EVKs))
	require.Equal(t, RotationKey, entry.EVKs[0].Type)

	expectedGalEl := params.GaloisElementForColumnRotationBy(5)
	require.Equal(t, expectedGalEl, entry.EVKs[0].GaloisEl)
}

func TestTracerRotateZero(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())

	// Rotate by k=0: no EVK needed (just a copy)
	tracer.Rotate(ct0, 0, ctOut)

	trace := tracer.GetTrace()
	require.Equal(t, 1, len(trace.Entries))
	require.Empty(t, trace.Entries[0].EVKs)
}

func TestTracerRescaleLevelDrop(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale()*params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, 0)

	// Rescale should reduce level
	err := tracer.Rescale(ct0, params.Scale()/2, ctOut)
	require.NoError(t, err)

	trace := tracer.GetTrace()
	require.Equal(t, 1, len(trace.Entries))

	entry := trace.Entries[0]
	require.Equal(t, "Rescale", entry.OpType)
	require.Equal(t, 3, entry.InputLevel)
	require.Less(t, entry.OutputLevel, entry.InputLevel, "Rescale should decrease level")
	require.Empty(t, entry.EVKs, "Rescale should not require EVKs")

	// Verify ctOut level matches
	require.Equal(t, entry.OutputLevel, ctOut.Level())
}

func TestTracerDropLevel(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())

	// DropLevel by 2 should change level from 3 to 1
	tracer.DropLevel(ct0, 2)

	trace := tracer.GetTrace()
	require.Equal(t, 1, len(trace.Entries))
	require.Equal(t, 3, trace.Entries[0].InputLevel)
	require.Equal(t, 1, trace.Entries[0].OutputLevel)

	// DropLevel modifies the ciphertext in-place
	require.Equal(t, 1, ct0.Level())
}

func TestTracerConjugate(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())

	tracer.Conjugate(ct0, ctOut)

	trace := tracer.GetTrace()
	require.Equal(t, 1, len(trace.Entries))

	entry := trace.Entries[0]
	require.Equal(t, "Conjugate", entry.OpType)
	require.Equal(t, 1, len(entry.EVKs))
	require.Equal(t, RotationKey, entry.EVKs[0].Type)
	require.Equal(t, params.GaloisElementForRowRotation(), entry.EVKs[0].GaloisEl)
}

func TestTracerRotateHoisted(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())

	// RotateHoisted with multiple rotations
	result := tracer.RotateHoisted(ct0, []int{0, 1, 3, 5})

	trace := tracer.GetTrace()
	require.Equal(t, 1, len(trace.Entries))

	entry := trace.Entries[0]
	require.Equal(t, "RotateHoisted", entry.OpType)
	// k=0 should not generate an EVK; k=1,3,5 should
	require.Equal(t, 3, len(entry.EVKs))

	// Verify all output ciphertexts exist
	require.Equal(t, 4, len(result))
	for _, k := range []int{0, 1, 3, 5} {
		require.NotNil(t, result[k])
		require.Equal(t, 3, result[k].Level())
	}
}

func TestTracerSequence(t *testing.T) {
	// Tests a realistic sequence: Add -> MulRelin -> Rescale -> Rotate
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	ct1 := newTracerCiphertext(params, 1, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())

	// Add (level 3 -> 3)
	tracer.Add(ct0, ct1, ctOut)

	// MulRelin (level 3 -> 3, scale squared)
	ctMul := newTracerCiphertext(params, 1, 3, 0)
	tracer.MulRelin(ctOut, ct1, ctMul)

	// Rescale (level 3 -> 2ish)
	ctResc := newTracerCiphertext(params, 1, 3, 0)
	err := tracer.Rescale(ctMul, params.Scale()/2, ctResc)
	require.NoError(t, err)

	// Rotate (at rescaled level)
	ctRot := newTracerCiphertext(params, 1, ctResc.Level(), 0)
	tracer.Rotate(ctResc, 7, ctRot)

	trace := tracer.GetTrace()
	require.Equal(t, 4, len(trace.Entries))

	// Verify operation types
	require.Equal(t, "Add", trace.Entries[0].OpType)
	require.Equal(t, "MulRelin", trace.Entries[1].OpType)
	require.Equal(t, "Rescale", trace.Entries[2].OpType)
	require.Equal(t, "Rotate", trace.Entries[3].OpType)

	// Verify EVK usage
	require.Empty(t, trace.Entries[0].EVKs)
	require.Equal(t, 1, len(trace.Entries[1].EVKs)) // relin key
	require.Empty(t, trace.Entries[2].EVKs)
	require.Equal(t, 1, len(trace.Entries[3].EVKs)) // rotation key

	// Verify level flow
	require.Equal(t, 3, trace.Entries[0].OutputLevel) // Add preserves level
	require.Equal(t, 3, trace.Entries[1].OutputLevel) // MulRelin preserves level
	require.Less(t, trace.Entries[2].OutputLevel, 3)  // Rescale drops level
	// Rotate preserves whatever level it gets
	require.Equal(t, trace.Entries[2].OutputLevel, trace.Entries[3].InputLevel)
}

func TestTracerNewVariants(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	ct1 := newTracerCiphertext(params, 1, 3, params.Scale())

	// Test *New variants return correctly-shaped ciphertexts
	ctAdd := tracer.AddNew(ct0, ct1)
	require.Equal(t, 3, ctAdd.Level())
	require.Equal(t, 1, ctAdd.Degree())

	ctMul := tracer.MulRelinNew(ct0, ct1)
	require.Equal(t, 3, ctMul.Level())
	require.Equal(t, 1, ctMul.Degree())

	ctRot := tracer.RotateNew(ct0, 3)
	require.Equal(t, 3, ctRot.Level())
	require.Equal(t, 1, ctRot.Degree())

	ctNeg := tracer.NegNew(ct0)
	require.Equal(t, 3, ctNeg.Level())

	trace := tracer.GetTrace()
	require.Equal(t, 4, len(trace.Entries))
}

func TestTracerWithKey(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	// WithKey should return the same tracer (keys are unused)
	copy := tracer.WithKey(rlwe.EvaluationKey{})
	require.NotNil(t, copy)

	ct0 := newTracerCiphertext(params, 1, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())
	copy.(*TracingEvaluator).Rotate(ct0, 1, ctOut)

	// Should share the same trace
	require.Equal(t, 1, len(tracer.GetTrace().Entries))
}

func TestTracerRelinearize(t *testing.T) {
	params := testParams()
	tracer := NewTracingEvaluator(params)

	// Degree-2 ciphertext
	ct0 := newTracerCiphertext(params, 2, 3, params.Scale())
	ctOut := newTracerCiphertext(params, 1, 3, params.Scale())

	tracer.Relinearize(ct0, ctOut)

	trace := tracer.GetTrace()
	require.Equal(t, 1, len(trace.Entries))
	require.Equal(t, "Relinearize", trace.Entries[0].OpType)
	require.Equal(t, 1, len(trace.Entries[0].EVKs))
	require.Equal(t, RelinKey, trace.Entries[0].EVKs[0].Type)
}
