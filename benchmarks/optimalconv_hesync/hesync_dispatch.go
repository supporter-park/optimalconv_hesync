package main

import (
	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/hesync"
)

// pagedBtp, when non-nil, diverts all Bootstrapper calls through a HESync
// PagedBootstrapper that loads boot rotkeys from disk on demand. Declared as
// a package global rather than a context field to keep context.struct
// backwards-compatible with existing code that constructs it positionally.
var pagedBtp *hesync.PagedBootstrapper

// hesyncTracing, when true, causes bootstrap dispatch to return zero-valued
// ciphertexts at max level instead of running the real bootstrap. This lets
// the HESync tracing phase walk the workload without crashing on fake tracer
// ciphertexts.
var hesyncTracing bool

// makeTracerCt returns a minimal ciphertext with the given level and scale,
// suitable as a stand-in for bootstrap output during tracing.
func makeTracerCt(params ckks.Parameters, level int, scale float64) *ckks.Ciphertext {
	return ckks.NewCiphertext(params, 1, level, scale)
}

// btpCtoS dispatches to the right bootstrapper instance (btp..btp5) selected
// by logSparse, routing through the paged bootstrapper when HESync is active.
func (cont *context) btpCtoS(logSparse int, ct *ckks.Ciphertext) (*ckks.Ciphertext, *ckks.Ciphertext, float64) {
	if hesyncTracing {
		// Bootstrap output lives at MaxLevel with the default scale.
		maxLvl := cont.params.MaxLevel()
		scale := cont.params.Scale()
		return makeTracerCt(cont.params, maxLvl, scale), makeTracerCt(cont.params, maxLvl, scale), 1.0
	}
	if pagedBtp != nil {
		return pagedBtp.BootstrappConv_CtoS(logSparse, ct)
	}
	switch logSparse {
	case 0:
		return cont.btp.BootstrappConv_CtoS(ct)
	case 1:
		return cont.btp2.BootstrappConv_CtoS(ct)
	case 2:
		return cont.btp3.BootstrappConv_CtoS(ct)
	case 3:
		return cont.btp4.BootstrappConv_CtoS(ct)
	case 4:
		return cont.btp5.BootstrappConv_CtoS(ct)
	default:
		panic("btpCtoS: logSparse out of range")
	}
}

// btpStoC dispatches to the right bootstrapper instance for the StoC phase.
func (cont *context) btpStoC(logSparse int, ct0, ct1 *ckks.Ciphertext) *ckks.Ciphertext {
	if hesyncTracing {
		return makeTracerCt(cont.params, cont.params.MaxLevel()-3, cont.params.Scale())
	}
	if pagedBtp != nil {
		return pagedBtp.BootstrappConv_StoC(logSparse, ct0, ct1)
	}
	switch logSparse {
	case 0:
		return cont.btp.BootstrappConv_StoC(ct0, ct1)
	case 1:
		return cont.btp2.BootstrappConv_StoC(ct0, ct1)
	case 2:
		return cont.btp3.BootstrappConv_StoC(ct0, ct1)
	case 3:
		return cont.btp4.BootstrappConv_StoC(ct0, ct1)
	case 4:
		return cont.btp5.BootstrappConv_StoC(ct0, ct1)
	default:
		panic("btpStoC: logSparse out of range")
	}
}

// btpBootstrapp dispatches a full Bootstrapp call (used by BL_Conv path).
func (cont *context) btpBootstrapp(logSparse int, ct *ckks.Ciphertext) *ckks.Ciphertext {
	if hesyncTracing {
		return makeTracerCt(cont.params, cont.params.MaxLevel()-3, cont.params.Scale())
	}
	if pagedBtp != nil {
		return pagedBtp.Bootstrapp(logSparse, ct)
	}
	switch logSparse {
	case 0:
		return cont.btp.Bootstrapp(ct)
	case 1:
		return cont.btp2.Bootstrapp(ct)
	case 2:
		return cont.btp3.Bootstrapp(ct)
	case 3:
		return cont.btp4.Bootstrapp(ct)
	case 4:
		return cont.btp5.Bootstrapp(ct)
	default:
		panic("btpBootstrapp: logSparse out of range")
	}
}
