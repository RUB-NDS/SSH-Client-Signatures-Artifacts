package main

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"filippo.io/edwards25519"
	"fmt"
	"go.linecorp.com/garr/queue"
	"golang.org/x/crypto/ssh"
	"log"
	"math/big"
	"sync"
	"time"
)

const (
	NonceDeterministicRFC6979 = iota
	NonceDeterministicRFC6979Variant
	NonceDeterministicProtoK
	NonceDeterministicEd25519
	NonceDeterministicUnknownMethod
	NonceDeterminismUndetermined
	NonceRandomlyGenerated
)

func sampleSignature(config *ssh.ServerConfig, timeout int) error {
	wg := sync.WaitGroup{}
	wg.Add(1)
	finish := make(chan bool)
	go RunServer(0, config, timeout, &wg, finish)
	log.Printf("> Connect to the server on 0.0.0.0:2200 to sample a signature for analysis")
	time.Sleep(1 * time.Second)
	close(finish)
	wg.Wait()
	return nil
}

func rfc6979Dsa(hash crypto.Hash, privKey *dsa.PrivateKey, signedData []byte, variant bool) *big.Int {
	// Parameter sizes
	holen := hash.Size()
	qlen := privKey.Q.BitLen()
	rolen := (qlen + 7) >> 3

	// Conversion functions for RFC6979 nonce generation
	bits2int := func(b []byte) *big.Int {
		v := new(big.Int).SetBytes(b)
		vlen := len(b) * 8
		if vlen > qlen {
			v = v.Rsh(v, uint(vlen-qlen))
		}
		return v
	}
	int2octets := func(v *big.Int) []byte {
		out := v.Bytes()
		if len(out) < rolen {
			out2 := make([]byte, rolen)
			copy(out2[rolen-len(out):], out)
			return out2
		} else if len(out) > rolen {
			out2 := make([]byte, rolen)
			copy(out2, out[len(out)-rolen:])
			return out2
		} else {
			return out
		}
	}
	bits2octets := func(b []byte) []byte {
		z1 := bits2int(b)
		z2 := new(big.Int).Sub(z1, privKey.Q)
		if z2.Sign() < 0 {
			return int2octets(z1)
		} else {
			return int2octets(z2)
		}
	}

	bx := int2octets(privKey.X)

	// a. Process m through the hash function H, yielding: h1 = H(m)
	hashedData := hash.New()
	hashedData.Write(signedData)
	h1 := hashedData.Sum(nil)
	var bh []byte
	if !variant {
		bh = bits2octets(h1)
	} else {
		// Section 3.6 Point 1:
		//    It is possible to use H(m) directly, instead of bits2octets(H(m)),
		//    as part of the HMAC input.  As explained in Section 3.5, we use
		//    bits2octets(H(m)) in order to ease integration into systems that
		//    already use an (EC)DSA signature engine by sending it an already-
		//    truncated hash value.  Using the whole H(m) does not introduce any
		//    vulnerability.
		bh = h1
	}

	V := make([]byte, holen)
	K := make([]byte, holen)
	for i := 0; i < holen; i++ {
		// b. Set V = 0x01 0x01 ... 0x01
		V[i] = 0x01
		// c. Set K = 0x00 0x00 ... 0x00
		K[i] = 0x00
	}

	// d. Set K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
	mac := hmac.New(hash.New, K)
	mac.Write(V)
	mac.Write([]byte{0x00})
	mac.Write(bx)
	mac.Write(bh)
	K = mac.Sum(nil)

	// e. Set V = HMAC_K(V)
	mac = hmac.New(hash.New, K)
	mac.Write(V)
	V = mac.Sum(nil)

	// f. Set K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
	mac = hmac.New(hash.New, K)
	mac.Write(V)
	mac.Write([]byte{0x01})
	mac.Write(bx)
	mac.Write(bh)
	K = mac.Sum(nil)

	// g. Set V = HMAC_K(V)
	mac = hmac.New(hash.New, K)
	mac.Write(V)
	V = mac.Sum(nil)

	// h. Apply the following algorithm until a proper value is found for k
	for {
		// 1. Set T to the empty sequence.  The length of T (in bits) is denoted tlen; thus, at that point, tlen = 0.
		var T []byte
		// 2. While tlen < qlen, do the following:
		for len(T) < rolen {
			// V = HMAC_K(V)
			// T = T || V
			mac = hmac.New(hash.New, K)
			mac.Write(V)
			V = mac.Sum(nil)
			T = append(T, V...)
		}
		// 3. Compute k = bits2int(T)
		k := bits2int(T)
		r := new(big.Int)
		r = r.Exp(privKey.G, k, privKey.P)
		r = r.Mod(r, privKey.Q)
		// If that value of k is within the [1,q-1] range, and is
		// suitable for DSA or ECDSA (i.e., it results in an r value
		// that is not 0; see Section 3.4), then the generation of k is
		// finished.
		if k.Cmp(big.NewInt(0)) > 0 &&
			k.Cmp(privKey.Q) < 0 &&
			r.Cmp(big.NewInt(0)) != 0 {
			return k
		}
		// K = HMAC_K(V || 0x00)
		// V = HMAC_K(V)
		mac = hmac.New(hash.New, K)
		mac.Write(V)
		mac.Write([]byte{0x00})
		K = mac.Sum(nil)
		mac = hmac.New(hash.New, K)
		mac.Write(V)
		V = mac.Sum(nil)
	}
}

func protoKDsa(idString string, privKey *dsa.PrivateKey, signedData []byte) *big.Int {
	h := crypto.SHA1.New()
	h.Write(signedData)
	dataDigest := h.Sum(nil)

	h = crypto.SHA512.New()
	// Write id string null-terminated
	h.Write([]byte(idString))
	h.Write([]byte{0x00})
	// Encode private key as mpint
	highestBitSet := privKey.X.Bytes()[0] >> 7 & 1
	privKeyLength := len(privKey.X.Bytes()) + int(highestBitSet)
	privKeyLengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(privKeyLengthBytes, uint32(privKeyLength))
	h.Write(privKeyLengthBytes)
	if highestBitSet == 1 {
		h.Write([]byte{0x00})
	}
	h.Write(privKey.X.Bytes())
	privKeyDigest := h.Sum(nil)

	h.Reset()
	h.Write(privKeyDigest)
	h.Write(dataDigest)

	protok := new(big.Int).SetBytes(h.Sum(nil))
	bigTwo := big.NewInt(2)
	modminus2 := new(big.Int).Sub(privKey.Q, bigTwo)
	protok.Mod(protok, modminus2)
	k := new(big.Int).Add(protok, bigTwo)
	return k
}

func rfc6979Ecdsa(hash crypto.Hash, privKey *ecdsa.PrivateKey, signedData []byte, variant bool) *big.Int {
	// Parameter sizes
	holen := hash.Size()
	qlen := privKey.Params().N.BitLen()
	rolen := (qlen + 7) >> 3

	// Conversion functions for RFC6979 nonce generation
	bits2int := func(b []byte) *big.Int {
		v := new(big.Int).SetBytes(b)
		vlen := len(b) * 8
		if vlen > qlen {
			v = v.Rsh(v, uint(vlen-qlen))
		}
		return v
	}
	int2octets := func(v *big.Int) []byte {
		out := v.Bytes()
		if len(out) < rolen {
			out2 := make([]byte, rolen)
			copy(out2[rolen-len(out):], out)
			return out2
		} else if len(out) > rolen {
			out2 := make([]byte, rolen)
			copy(out2, out[len(out)-rolen:])
			return out2
		} else {
			return out
		}
	}
	bits2octets := func(b []byte) []byte {
		z1 := bits2int(b)
		z2 := new(big.Int).Sub(z1, privKey.Params().N)
		if z2.Sign() < 0 {
			return int2octets(z1)
		} else {
			return int2octets(z2)
		}
	}

	bx := int2octets(privKey.D)

	// a. Process m through the hash function H, yielding: h1 = H(m)
	hashedData := hash.New()
	hashedData.Write(signedData)
	h1 := hashedData.Sum(nil)
	var bh []byte
	if !variant {
		bh = bits2octets(h1)
	} else {
		// Section 3.6 Point 1:
		//    It is possible to use H(m) directly, instead of bits2octets(H(m)),
		//    as part of the HMAC input.  As explained in Section 3.5, we use
		//    bits2octets(H(m)) in order to ease integration into systems that
		//    already use an (EC)DSA signature engine by sending it an already-
		//    truncated hash value.  Using the whole H(m) does not introduce any
		//    vulnerability.
		bh = h1
	}

	V := make([]byte, holen)
	K := make([]byte, holen)
	for i := 0; i < holen; i++ {
		// b. Set V = 0x01 0x01 ... 0x01
		V[i] = 0x01
		// c. Set K = 0x00 0x00 ... 0x00
		K[i] = 0x00
	}

	// d. Set K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
	mac := hmac.New(hash.New, K)
	mac.Write(V)
	mac.Write([]byte{0x00})
	mac.Write(bx)
	mac.Write(bh)
	K = mac.Sum(nil)

	// e. Set V = HMAC_K(V)
	mac = hmac.New(hash.New, K)
	mac.Write(V)
	V = mac.Sum(nil)

	// f. Set K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
	mac = hmac.New(hash.New, K)
	mac.Write(V)
	mac.Write([]byte{0x01})
	mac.Write(bx)
	mac.Write(bh)
	K = mac.Sum(nil)

	// g. Set V = HMAC_K(V)
	mac = hmac.New(hash.New, K)
	mac.Write(V)
	V = mac.Sum(nil)

	// h. Apply the following algorithm until a proper value is found for k
	for {
		// 1. Set T to the empty sequence.  The length of T (in bits) is denoted tlen; thus, at that point, tlen = 0.
		var T []byte
		// 2. While tlen < qlen, do the following:
		for len(T) < rolen {
			// V = HMAC_K(V)
			// T = T || V
			mac = hmac.New(hash.New, K)
			mac.Write(V)
			V = mac.Sum(nil)
			T = append(T, V...)
		}
		// 3. Compute k = bits2int(T)
		k := bits2int(T)
		r, _ := privKey.ScalarBaseMult(k.Bytes())
		// If that value of k is within the [1,q-1] range, and is
		// suitable for DSA or ECDSA (i.e., it results in an r value
		// that is not 0; see Section 3.4), then the generation of k is
		// finished.
		if k.Cmp(big.NewInt(0)) > 0 &&
			k.Cmp(privKey.Params().N) < 0 &&
			r.Cmp(big.NewInt(0)) != 0 {
			return k
		}
		// K = HMAC_K(V || 0x00)
		// V = HMAC_K(V)
		mac = hmac.New(hash.New, K)
		mac.Write(V)
		mac.Write([]byte{0x00})
		K = mac.Sum(nil)
		mac = hmac.New(hash.New, K)
		mac.Write(V)
		V = mac.Sum(nil)
	}
}

func protoKEcdsa(idString string, privKey *ecdsa.PrivateKey, signedData []byte) *big.Int {
	h := crypto.SHA1.New()
	h.Write(signedData)
	dataDigest := h.Sum(nil)

	h = crypto.SHA512.New()
	// Write id string null-terminated
	h.Write([]byte(idString))
	h.Write([]byte{0x00})
	// Encode private key as mpint
	highestBitSet := privKey.D.Bytes()[0] >> 7 & 1
	privKeyLength := len(privKey.D.Bytes()) + int(highestBitSet)
	privKeyLengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(privKeyLengthBytes, uint32(privKeyLength))
	h.Write(privKeyLengthBytes)
	if highestBitSet == 1 {
		h.Write([]byte{0x00})
	}
	h.Write(privKey.D.Bytes())
	privKeyDigest := h.Sum(nil)

	h.Reset()
	h.Write(privKeyDigest)
	h.Write(dataDigest)

	protok := new(big.Int).SetBytes(h.Sum(nil))
	bigTwo := big.NewInt(2)
	modminus2 := new(big.Int).Sub(privKey.Params().N, bigTwo)
	protok.Mod(protok, modminus2)
	k := new(big.Int).Add(protok, bigTwo)
	return k
}

func rfc8032Ed25519(privKey *ed25519.PrivateKey, signedData []byte) (*edwards25519.Scalar, error) {
	seed := (*privKey)[:32]
	hashFunc := sha512.New()
	hashFunc.Write(seed)
	h := hashFunc.Sum(nil)

	prefix := h[32:]
	hashFunc.Reset()
	hashFunc.Write(prefix)
	hashFunc.Write(signedData)
	rBytes := hashFunc.Sum(nil)
	r, err := edwards25519.NewScalar().SetUniformBytes(rBytes)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func checkDeterminismDsa(nonces []*SampledDsaNonce, privKey *dsa.PrivateKey) int {
	log.Printf("> Checking nonce generation determinism with %d signatures available.", len(nonces))
	log.Printf("> First sampled nonce: k = %s", nonces[0].k.Text(16))

	rfc6979Nonce := rfc6979Dsa(HashFuncs[nonces[0].SampledDsaSignature.signatureFormat],
		privKey,
		nonces[0].SampledDsaSignature.signedData, false)
	log.Printf("> Corresponding RFC6979 nonce: k = %s", rfc6979Nonce.Text(16))
	rfc6979VariantNonce := rfc6979Dsa(HashFuncs[nonces[0].SampledDsaSignature.signatureFormat],
		privKey,
		nonces[0].SampledDsaSignature.signedData, true)
	log.Printf("> Corresponding RFC6979 variant nonce: k = %s", rfc6979VariantNonce.Text(16))
	protoKNonce := protoKDsa("ECDSA deterministic k generator",
		privKey,
		nonces[0].SampledDsaSignature.signedData)
	log.Printf("> Corresponding proto_k nonce: k = %s", protoKNonce.Text(16))

	if rfc6979Nonce.Cmp(nonces[0].k) == 0 {
		return NonceDeterministicRFC6979
	}
	if rfc6979VariantNonce.Cmp(nonces[0].k) == 0 {
		return NonceDeterministicRFC6979Variant
	}
	if protoKNonce.Cmp(nonces[0].k) == 0 {
		return NonceDeterministicProtoK
	}

	if len(nonces) < 2 {
		return NonceDeterminismUndetermined
	}
	if nonces[0].k.Cmp(nonces[1].k) == 0 {
		return NonceDeterministicUnknownMethod
	}
	return NonceRandomlyGenerated
}

func checkDeterminismEcdsa(nonces []*SampledEcdsaNonce, privKey *ecdsa.PrivateKey) int {
	log.Printf("> Checking nonce generation determinism with %d signatures available.", len(nonces))
	log.Printf("> First sampled nonce: k = %s", nonces[0].k.Text(16))

	rfc6979Nonce := rfc6979Ecdsa(HashFuncs[nonces[0].SampledEcdsaSignature.signatureFormat],
		privKey,
		nonces[0].SampledEcdsaSignature.signedData, false)
	log.Printf("> Corresponding RFC6979 nonce: k = %s", rfc6979Nonce.Text(16))
	rfc6979VariantNonce := rfc6979Ecdsa(HashFuncs[nonces[0].SampledEcdsaSignature.signatureFormat],
		privKey,
		nonces[0].SampledEcdsaSignature.signedData, true)
	log.Printf("> Corresponding RFC6979 variant nonce: k = %s", rfc6979VariantNonce.Text(16))
	protoKNonce := protoKEcdsa("ECDSA deterministic k generator",
		privKey,
		nonces[0].SampledEcdsaSignature.signedData)
	log.Printf("> Corresponding proto_k nonce: k = %s", protoKNonce.Text(16))

	if rfc6979Nonce.Cmp(nonces[0].k) == 0 {
		return NonceDeterministicRFC6979
	}
	if rfc6979VariantNonce.Cmp(nonces[0].k) == 0 {
		return NonceDeterministicRFC6979Variant
	}
	if protoKNonce.Cmp(nonces[0].k) == 0 {
		return NonceDeterministicProtoK
	}

	if len(nonces) < 2 {
		return NonceDeterminismUndetermined
	}
	if nonces[0].k.Cmp(nonces[1].k) == 0 {
		return NonceDeterministicUnknownMethod
	}
	return NonceRandomlyGenerated
}

func checkDeterminismEd25519(nonces []*SampledEd25519Nonce, privKey *ed25519.PrivateKey) int {
	log.Printf("> Checking nonce generation determinism with %d signatures available.", len(nonces))
	log.Printf("> First sampled nonce: r = %s", hex.EncodeToString(nonces[0].r.Bytes()))

	ed25519Nonce, err := rfc8032Ed25519(
		privKey,
		nonces[0].SampledEd25519Signature.signedData)
	if err != nil {
		log.Printf("> Error computing RFC8032 ED25519 nonce: %v", err)
		return NonceDeterminismUndetermined
	}
	log.Printf("> Corresponding ED25519 nonce: r = %s", hex.EncodeToString(ed25519Nonce.Bytes()))

	if ed25519Nonce.Equal(nonces[0].r) == 1 {
		return NonceDeterministicEd25519
	}

	if len(nonces) < 2 {
		return NonceDeterminismUndetermined
	}
	if nonces[0].r.Equal(nonces[1].r) == 1 {
		return NonceDeterministicUnknownMethod
	}
	return NonceRandomlyGenerated
}

func RunDeterminismAnalysis(timeout int, privKeyFile string, agent bool) error {
	privKey, err := LoadPrivateKeyFromFile(privKeyFile)
	if err != nil {
		return err
	}
	privKeySigner, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return err
	}
	sigQueue := queue.DefaultQueue()
	if !agent {
		config, err := ConstructServerConfig(&sigQueue, &privKeySigner)
		if err != nil {
			return err
		}
		if err := sampleSignature(config, timeout); err != nil {
			return err
		}
	} else {
		err := SampleAgentSignatures(2, true, &sigQueue, privKey)
		if err != nil {
			return err
		}
	}
	switch privKeySigner.PublicKey().Type() {
	case ssh.KeyAlgoDSA:
		nonces := RecoverDsaNonces(&sigQueue, privKey.(*dsa.PrivateKey), 1)
		switch checkDeterminismDsa(nonces, privKey.(*dsa.PrivateKey)) {
		case NonceDeterministicRFC6979:
			log.Println("==> Detected deterministic nonce generation using RFC6979 method")
		case NonceDeterministicRFC6979Variant:
			log.Println("==> Detected deterministic nonce generation using RFC6979 variant method")
		case NonceDeterministicProtoK:
			log.Println("==> Detected deterministic nonce generation using proto_k method")
		case NonceDeterministicUnknownMethod:
			log.Println("==> Detected deterministic nonce generation using an unknown method")
		case NonceDeterminismUndetermined:
			log.Println("==> Unable to determine nonce generation determinism with the available signatures")
		case NonceRandomlyGenerated:
			log.Println("==> Detected randomly generated nonces")
		default:
			// This should never happen
		}
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		nonces := RecoverEcdsaNonces(&sigQueue, privKey.(*ecdsa.PrivateKey), 1)
		if len(nonces) == 0 {
			return fmt.Errorf("no nonces recovered from the sampled signatures")
		}
		switch checkDeterminismEcdsa(nonces, privKey.(*ecdsa.PrivateKey)) {
		case NonceDeterministicRFC6979:
			log.Println("==> Detected deterministic nonce generation using RFC6979 method")
		case NonceDeterministicRFC6979Variant:
			log.Println("==> Detected deterministic nonce generation using RFC6979 variant method")
		case NonceDeterministicProtoK:
			log.Println("==> Detected deterministic nonce generation using proto_k method")
		case NonceDeterministicUnknownMethod:
			log.Println("==> Detected deterministic nonce generation using an unknown method")
		case NonceDeterminismUndetermined:
			log.Println("==> Unable to determine nonce generation determinism with the available signatures")
		case NonceRandomlyGenerated:
			log.Println("==> Detected randomly generated nonces")
		default:
			// This should never happen
		}
	case ssh.KeyAlgoED25519:
		nonces := RecoverEd25519Nonces(&sigQueue, privKey.(*ed25519.PrivateKey), 1)
		if len(nonces) == 0 {
			return fmt.Errorf("no nonces recovered from the sampled signatures")
		}
		switch checkDeterminismEd25519(nonces, privKey.(*ed25519.PrivateKey)) {
		case NonceDeterministicEd25519:
			log.Println("==> Detected deterministic nonce generation using Ed25519 method")
		case NonceDeterministicUnknownMethod:
			log.Println("==> Detected deterministic nonce generation using an unknown method")
		case NonceDeterminismUndetermined:
			log.Println("==> Unable to determine nonce generation determinism with the available signatures")
		case NonceRandomlyGenerated:
			log.Println("==> Detected randomly generated nonces")
		default:
			// This should never happen
		}
	}
	return nil
}
