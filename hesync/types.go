package hesync

import "fmt"

// EVKType distinguishes the kind of evaluation key.
type EVKType int

const (
	RelinKey    EVKType = iota // Relinearization key
	RotationKey                // Rotation key (indexed by Galois element)
)

// EVKIdentifier uniquely identifies a single evaluation key (one SwitchingKey).
type EVKIdentifier struct {
	Type     EVKType
	GaloisEl uint64 // Galois element for rotation keys; 0 for relin key
}

func (id EVKIdentifier) String() string {
	switch id.Type {
	case RelinKey:
		return fmt.Sprintf("relin_%d", id.GaloisEl)
	case RotationKey:
		return fmt.Sprintf("rot_%d", id.GaloisEl)
	default:
		return fmt.Sprintf("unknown_%d_%d", id.Type, id.GaloisEl)
	}
}

// Filename returns the disk filename for this EVK.
func (id EVKIdentifier) Filename() string {
	return fmt.Sprintf("evk_%s.bin", id.String())
}

// PlanCriterion selects which profiled level timing the Planner uses
// to estimate operation durations when scheduling prefetches.
type PlanCriterion int

const (
	CriterionLevel0   PlanCriterion = iota // Use level-0 profile (fastest ops, most prefetch slack)
	CriterionHalfMax                       // Use maxLevel/2 profile
	CriterionMaxLevel                      // Use maxLevel profile (slowest ops, least slack)
	CriterionPerTrace                      // Use each entry's actual level (HESync design target)
	CriterionLazyLoad                      // Load EVKs at the start of each operation (no prefetch)
)

func (c PlanCriterion) String() string {
	switch c {
	case CriterionLevel0:
		return "Level0"
	case CriterionHalfMax:
		return "HalfMax"
	case CriterionMaxLevel:
		return "MaxLevel"
	case CriterionPerTrace:
		return "PerTrace"
	case CriterionLazyLoad:
		return "LazyLoad"
	default:
		return "Unknown"
	}
}

// InstructionType is the type of a plan instruction.
type InstructionType int

const (
	Nop   InstructionType = iota // No prefetch action
	Fetch                        // Begin loading EVK(s) from storage
	Sync                         // Block until EVK(s) have been loaded
)

func (t InstructionType) String() string {
	switch t {
	case Nop:
		return "Nop"
	case Fetch:
		return "Fetch"
	case Sync:
		return "Sync"
	default:
		return "Unknown"
	}
}
