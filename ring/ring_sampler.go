package ring

import (
	"github.com/supporter-park/optimalconv_hesync/utils"
)

const precision = uint64(56)

type baseSampler struct {
	prng     utils.PRNG
	baseRing *Ring
}
