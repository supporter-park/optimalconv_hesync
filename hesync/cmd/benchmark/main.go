package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/supporter-park/optimalconv_hesync/ckks"
	"github.com/supporter-park/optimalconv_hesync/hesync"
	"github.com/supporter-park/optimalconv_hesync/rlwe"
	"github.com/supporter-park/optimalconv_hesync/utils"
)

func main() {
	var (
		outputFile   = flag.String("output", "results.txt", "Output file for benchmark results")
		evkDir       = flag.String("evkdir", "/tmp/hesync_evks", "Directory for EVK storage")
		criterion    = flag.Int("criterion", -1, "Plan criterion (0=Level0, 1=HalfMax, 2=MaxLevel, 3=PerTrace, -1=all)")
		profileIters = flag.Int("profile-iters", 3, "Number of profiler iterations")
		logN         = flag.Int("logN", 13, "Log of ring dimension (default 13 for testing, 16 for production)")
		numRotations = flag.Int("rotations", 8, "Number of distinct rotation keys to use in the demo workload")
	)
	flag.Parse()

	log.SetFlags(log.Ltime)

	// Select criteria
	var criteria []hesync.PlanCriterion
	if *criterion == -1 {
		criteria = []hesync.PlanCriterion{
			hesync.CriterionLevel0,
			hesync.CriterionHalfMax,
			hesync.CriterionMaxLevel,
			hesync.CriterionPerTrace,
		}
	} else {
		criteria = []hesync.PlanCriterion{hesync.PlanCriterion(*criterion)}
	}

	// Setup parameters
	var paramLit ckks.ParametersLiteral
	switch *logN {
	case 12:
		paramLit = ckks.PN12QP109
	case 13:
		paramLit = ckks.PN13QP218
	case 14:
		paramLit = ckks.PN14QP438
	case 15:
		paramLit = ckks.PN15QP880
	case 16:
		paramLit = ckks.PN16QP1761
	default:
		log.Fatalf("unsupported logN=%d (use 12-16)", *logN)
	}

	params, err := ckks.NewParametersFromLiteral(paramLit)
	if err != nil {
		log.Fatalf("failed to create parameters: %v", err)
	}
	log.Printf("Parameters: logN=%d, logSlots=%d, levels=%d, scale=%.0f",
		params.LogN(), params.LogSlots(), params.MaxLevel()+1, params.Scale())

	// Key generation
	log.Println("Generating keys...")
	kgen := ckks.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rlk := kgen.GenRelinearizationKey(sk, 2)

	rotations := make([]int, *numRotations)
	for i := range rotations {
		rotations[i] = i + 1
	}
	rotKeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	evk := rlwe.EvaluationKey{Rlk: rlk, Rtks: rotKeys}
	log.Printf("Generated %d rotation keys + relin key", *numRotations)

	// Encrypt test data
	log.Println("Encrypting test data...")
	encoder := ckks.NewEncoder(params)
	encryptor := ckks.NewEncryptor(params, sk)
	values := make([]complex128, params.Slots())
	for i := range values {
		values[i] = complex(float64(i)/float64(params.Slots()), 0)
	}
	pt := encoder.EncodeNew(values, params.LogSlots())
	ct := encryptor.EncryptNew(pt)

	// Define workload: a sequence of MulRelin + Rescale + Rotate operations
	// simulating a simplified CNN layer
	workload := func(eval ckks.Evaluator, ctIn *ckks.Ciphertext) *ckks.Ciphertext {
		prng, _ := utils.NewPRNG()
		result := ctIn

		for i := 0; i < *numRotations; i++ {
			// Multiply + relinearize
			tmp := ckks.NewCiphertext(params, 1, result.Level(), result.Scale)
			eval.MulRelin(result, result, tmp)

			// Rescale
			if tmp.Level() > 0 {
				rescaled := ckks.NewCiphertext(params, 1, tmp.Level(), tmp.Scale)
				eval.Rescale(tmp, params.Scale()/2, rescaled)
				tmp = rescaled
			}

			// Rotate
			if tmp.Level() > 0 {
				rotOut := ckks.NewCiphertext(params, 1, tmp.Level(), tmp.Scale)
				eval.Rotate(tmp, rotations[i], rotOut)
				result = rotOut
			} else {
				result = tmp
			}
		}

		_ = prng
		return result
	}

	// Run benchmark
	log.Printf("Running benchmark with %d criteria...", len(criteria))
	cfg := hesync.BenchmarkConfig{
		Params:       params,
		EvalKey:      evk,
		Criteria:     criteria,
		ProfileIters: *profileIters,
		EVKStoreDir:  *evkDir,
	}

	results, err := hesync.RunBenchmark(cfg, workload, ct)
	if err != nil {
		log.Fatalf("benchmark failed: %v", err)
	}

	// Write to stdout
	hesync.WriteResults(os.Stdout, results)

	// Write to file
	f, err := os.Create(*outputFile)
	if err != nil {
		log.Fatalf("failed to create output file: %v", err)
	}
	defer f.Close()
	hesync.WriteResults(f, results)
	fmt.Printf("Results written to %s\n", *outputFile)
}
