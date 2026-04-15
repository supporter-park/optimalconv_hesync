package bfv

import (
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/supporter-park/optimalconv_hesync/utils"
)

// Ciphertext is a *ring.Poly array representing a polynomial of degree > 0 with coefficients in R_Q.
type Ciphertext struct {
	*rlwe.Ciphertext
}

// NewCiphertext creates a new ciphertext parameterized by degree, level and scale.
func NewCiphertext(params Parameters, degree int) (ciphertext *Ciphertext) {
	return &Ciphertext{rlwe.NewCiphertext(params.Parameters, degree, params.MaxLevel())}
}

// NewCiphertextRandom generates a new uniformly distributed ciphertext of degree, level and scale.
func NewCiphertextRandom(prng utils.PRNG, params Parameters, degree int) (ciphertext *Ciphertext) {
	ciphertext = &Ciphertext{rlwe.NewCiphertext(params.Parameters, degree, params.MaxLevel())}
	rlwe.PopulateElementRandom(prng, params.Parameters, (*rlwe.Ciphertext)(ciphertext.Ciphertext))
	return
}

// CopyNew creates a deep copy of the receiver ciphertext and returns it.
func (ct *Ciphertext) CopyNew() *Ciphertext {
	return &Ciphertext{ct.Ciphertext.CopyNew()}
}
