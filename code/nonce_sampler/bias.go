package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"log"
	"math"
	"math/big"
	"math/cmplx"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"go.linecorp.com/garr/queue"
	"golang.org/x/crypto/ssh"
)

// sampleSignaturesContinuously samples signatures from an SSH server running on port 2200 + index.
func sampleSignaturesContinuously(index int, config *ssh.ServerConfig, cmdTemplate string, timeout int, wg *sync.WaitGroup, finish <-chan bool) {
	defer wg.Done()
	clientCmd := BuildClientCmd(cmdTemplate, "127.0.0.1", 2200+index)
	wg.Add(1)
	go RunServer(index, config, timeout, wg, finish)
	for {
		select {
		case <-finish:
			return
		default:
			_ = ConnectClient(clientCmd)
		}
	}
}

// CollectSignatures collects a minimum number of signatures from SSH user authentication. The function uses a number of
// workers to sample signatures concurrently. The number of workers should be equal to the number of CPU cores for
// optimal performance. The function returns a queue of SampledEcdsaSignature objects containing the sampled signatures.
func CollectSignatures(minSignatures int, workers int, cmdTemplate string, privKey *ssh.Signer, timeout int, noPartialSuccess bool) (*queue.Queue, error) {
	wg := sync.WaitGroup{}
	timeStart := time.Now()
	sigQueue := queue.DefaultQueue()
	config, err := ConstructServerConfig(&sigQueue, privKey, noPartialSuccess)
	if err != nil {
		return nil, err
	}
	finish := make(chan bool)
	log.Printf("> Collecting a minimum of %d signatures from SSH user authentication\n", minSignatures)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go sampleSignaturesContinuously(i, config, cmdTemplate, timeout, &wg, finish)
	}
	signatures := int(sigQueue.Size())
	for signatures < minSignatures {
		time.Sleep(time.Second)
		signaturesPrev := signatures
		signatures = int(sigQueue.Size())
		log.Printf("Gathered: %d\t| Remaining: %d\t| Last Second: %d\n",
			signatures,
			minSignatures-signatures,
			signatures-signaturesPrev,
		)
	}
	close(finish)
	wg.Wait()
	log.Printf("Collected a total of %d signatures in %.2f seconds\n", sigQueue.Size(), time.Now().Sub(timeStart).Seconds())
	return &sigQueue, nil
}

// bias computes the bias of a set of samples with respect to a modulus and a multiplier. The function returns the bias
// as a float64 value. The result of bias will be Rayleigh distributed with sigma = 1 / sqrt(2) if samples are uniform
// in [0, modulus - 1]. The function is based on the following implementation:
// https://github.com/C2SP/wycheproof/blob/master/java/com/google/security/wycheproof/testcases/EcdsaTest.java#L168
func bias(nonceSamples []*big.Int, modulus *big.Int, multiplier *big.Int) float64 {
	sum := 0 + 0i
	mf := new(big.Float).SetInt(multiplier)
	modf := new(big.Float).SetInt(modulus)
	for _, s := range nonceSamples {
		sf := new(big.Float).SetInt(s)
		// Compute r := s * m / modulo
		r, _ := sf.Mul(sf, mf).Quo(sf, modf).Float64()
		// Add up e^(2 * pi * i * r)
		sum += cmplx.Exp(2 * math.Pi * complex(0, r))
	}
	return cmplx.Abs(sum) / math.Sqrt(float64(len(nonceSamples)))
}

// testSampledNonceBias tests sampled nonces for potential bias. The function returns true if a bias is detected.
// Based on https://github.com/C2SP/wycheproof/blob/master/java/com/google/security/wycheproof/testcases/EcdsaTest.java#L363
func testSampledNonceBias(nonceSamples []*big.Int, modulus *big.Int) bool {
	// Output table column formats
	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnGoodFmt := color.New(color.FgGreen).SprintfFunc()
	columnBadFmt := color.New(color.FgRed, color.Bold).SprintfFunc()
	highlightSignificance := func(s bool) string {
		if s {
			return columnBadFmt("%t", s)
		} else {
			return columnGoodFmt("%t", s)
		}
	}

	log.Println("> Testing sampled nonces for potential bias")
	biasDetected := false

	// Compute decision threshold for individual bit bias
	// zCritical computed for alpha = 2^{-32} in two-tailed test
	const zCritical = 6.3379577545537895
	n := float64(len(nonceSamples))
	sLower := int(math.Round(n/2 - zCritical*math.Sqrt(n/4)))
	sUpper := int(math.Round(n/2 + zCritical*math.Sqrt(n/4)))

	// Prepare table for individual bit bias test results
	tbl := table.New("Index", "S", "S_lower", "S_upper", "H0 Rejection")
	tbl.WithHeaderFormatter(headerFmt)
	for i := 0; i < modulus.BitLen(); i++ {
		sum := 0
		for _, sample := range nonceSamples {
			sum += int(sample.Bit(i))
		}
		h0Rejection := sum < sLower || sum > sUpper
		tbl.AddRow(i, sum, sLower, sUpper, highlightSignificance(h0Rejection))
		if h0Rejection {
			biasDetected = true
		}
	}
	tbl.Print()

	// Prepare table for bias test results
	tbl = table.New("Multiplier", "Bias", "Threshold", "H0 Rejection")
	tbl.WithHeaderFormatter(headerFmt)

	// Perform bias checks with a threshold of 5 (=> false positive probability < 2^{-32})
	const threshold = 5
	for _, mult := range []string{
		// bias1
		"01",
		// bias2
		"02",
		// bias3
		new(big.Int).Rsh(modulus, 1).Text(16),
		// bias4
		"FF",
		"FFFF",
		"FFFFFFFF",
		"FFFFFFFFFFFFFFFF",
		// bias5
		"300020001FFF9FFFD00090005FFF8FFFE36B469D49B2B1B86B409",
		"B0000BFF4FAFF3F3B04F6C0CFFB0A0A2D1DB2882D6B85954F5AC2E9",
		"23AFFFFFD7E00000277FFFFFC27000003DA57311C6B4D9F1005E6D47F57",
		"4B088666FCF77998F4A6B827D661CE3F24AF75FA42EC07381C0E34F360",
		"9BEAC7904FB495C58CA26A3AF3CB3C4E0CA65224FB9A88B4073DDECE0DBF",
		"1FDAF45D2F75FB5DB16F94A2648FCDF6F9C93AA8785530B393470AAB86F0",
		"1000000010001FFFEFFFE0003010400FFBBE4FAAE22E90CB0364457",
	} {
		m, _ := new(big.Int).SetString(mult, 16)
		b := bias(nonceSamples, modulus, m)
		tbl.AddRow(m, b, threshold, highlightSignificance(b > threshold))
		if b > threshold {
			biasDetected = true
		}
	}
	// Print table and return bias test result
	tbl.Print()
	return biasDetected
}

// RunBiasAnalysis runs a bias analysis on sampled nonces. The function collects a minimum number of signatures from SSH
// user authentication and tests the sampled nonces for potential bias. The function returns an error if the bias test
// fails or if an error occurs during signature collection or nonce recovery. The function uses a number of workers to
// process the signatures concurrently. The number of workers should be equal to the number of CPU cores for optimal
// performance.
func RunBiasAnalysis(minSignatures int, workers int, cmdTemplate string, timeout int, privKeyFile string, agent bool, noPartialSuccess bool) error {
	privKey, err := LoadPrivateKeyFromFile(privKeyFile)
	if err != nil {
		return err
	}
	privKeySigner, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return err
	}

	var sigQueue *queue.Queue
	if !agent {
		sigQueue, err = CollectSignatures(
			minSignatures,
			workers,
			cmdTemplate,
			&privKeySigner,
			timeout,
			noPartialSuccess)
	} else {
		agentSigQueue := queue.DefaultQueue()
		err = SampleAgentSignatures(minSignatures, false, &agentSigQueue, privKey)
		sigQueue = &agentSigQueue
	}
	if err != nil {
		return err
	}
	var nonces []*big.Int
	var modulus *big.Int
	switch privKeySigner.PublicKey().Type() {
	case ssh.KeyAlgoDSA:
		samples := RecoverDsaNonces(sigQueue, privKey.(*dsa.PrivateKey), workers)
		nonces = make([]*big.Int, 0, len(samples))
		for _, sample := range samples {
			nonces = append(nonces, sample.k)
		}
		modulus = privKey.(*dsa.PrivateKey).Q
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		samples := RecoverEcdsaNonces(sigQueue, privKey.(*ecdsa.PrivateKey), workers)
		nonces = make([]*big.Int, 0, len(samples))
		for _, sample := range samples {
			nonces = append(nonces, sample.k)
		}
		modulus = privKey.(*ecdsa.PrivateKey).Params().N
	}
	biasDetected := testSampledNonceBias(nonces, modulus)
	if biasDetected {
		log.Println("==> Completed bias test, found possible nonce bias in sampled nonces")
	} else {
		log.Println("==> Completed bias test without detecting any bias")
	}
	return nil
}
