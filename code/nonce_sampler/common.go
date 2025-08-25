package main

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.linecorp.com/garr/queue"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"filippo.io/edwards25519"
)

// SampledDsaSignature is a struct to store a signature and the corresponding signed data.
type SampledDsaSignature struct {
	pubKeyType        string
	pubKeyFingerprint string
	signatureFormat   string
	signatureBlob     []byte

	signedData []byte
	r          *big.Int
	s          *big.Int
}

type SampledDsaNonce struct {
	SampledDsaSignature
	k *big.Int
}

// SampledEcdsaSignature is a struct to store a signature and the corresponding signed data.
type SampledEcdsaSignature struct {
	pubKeyType        string
	pubKeyFingerprint string
	signatureFormat   string
	signatureBlob     []byte

	signedData []byte
	r          *big.Int
	s          *big.Int
}

type SampledEcdsaNonce struct {
	SampledEcdsaSignature
	k *big.Int
}

// SampledEd25519Signature is a struct to store a signature and the corresponding signed data.
type SampledEd25519Signature struct {
	pubKeyType        string
	pubKeyFingerprint string
	signatureFormat   string
	signatureBlob     []byte

	signedData []byte
	R          *edwards25519.Point
	S          *edwards25519.Scalar
}

type SampledEd25519Nonce struct {
	SampledEd25519Signature
	r *edwards25519.Scalar
}

// HashFuncs maps ssh key algorithms to the hash functions used for pre-hashing.
var HashFuncs = map[string]crypto.Hash{
	ssh.KeyAlgoRSA:       crypto.SHA1,
	ssh.KeyAlgoRSASHA256: crypto.SHA256,
	ssh.KeyAlgoRSASHA512: crypto.SHA512,
	ssh.KeyAlgoDSA:       crypto.SHA1,
	ssh.KeyAlgoECDSA256:  crypto.SHA256,
	ssh.KeyAlgoECDSA384:  crypto.SHA384,
	ssh.KeyAlgoECDSA521:  crypto.SHA512,
	// KeyAlgoED25519 doesn't pre-hash.
	ssh.KeyAlgoSKECDSA256: crypto.SHA256,
	ssh.KeyAlgoSKED25519:  crypto.SHA256,
}

// LoadOrGenerateHostKey loads or generates an SSH host key for the server.
func LoadOrGenerateHostKey() (ssh.Signer, error) {
	var hostKey ssh.Signer
	if _, err := os.Stat("ssh_server_host_key"); err != nil {
		// Generate a new host key if it doesn't exist (use RSA for best compatibility)
		hostPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		hostKeyPem, err := ssh.MarshalPrivateKey(hostPrivKey, "")
		if err != nil {
			return nil, err
		}
		file, err := os.Create("ssh_server_host_key")
		if err != nil {
			return nil, err
		}
		if err = pem.Encode(file, hostKeyPem); err != nil {
			return nil, err
		}
		if err = file.Close(); err != nil {
			return nil, err
		}
		if hostKey, err = ssh.NewSignerFromKey(hostPrivKey); err != nil {
			return nil, err
		}
	} else {
		// Load the host key from the file
		hostKeyBytes, err := os.ReadFile("ssh_server_host_key")
		if err != nil {
			return nil, err
		}
		if hostKey, err = ssh.ParsePrivateKey(hostKeyBytes); err != nil {
			return nil, err
		}
	}
	return hostKey, nil
}

// ConstructServerConfig constructs an ssh.ServerConfig with a host key from the file "ssh_server_host_key".
// The server config only allows public key authentication and offers the public key to the signature queue.
// The signature queue is used to collect signatures for nonce recovery. The private key is used to verify the
// public key before offering the signature to the queue.
func ConstructServerConfig(sigQueue *queue.Queue, privKey *ssh.Signer, noPartialSuccess bool) (*ssh.ServerConfig, error) {
	hostKey, err := LoadOrGenerateHostKey()
	if err != nil {
		return nil, err
	}
	config := ssh.ServerConfig{
		// Do not limit the number of authentication attempts
		MaxAuthTries: -1,
		// Only allow public key authentication
		// We can use privKey.PublicKey().Type() to get the public key type since we don't care about RSA here
		PublicKeyAuthAlgorithms: []string{(*privKey).PublicKey().Type()},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
		PublicKeySignatureCallback: func(_ ssh.ConnMetadata, pubKey ssh.PublicKey, signedData []byte, sig *ssh.Signature) error {
			// Check if the public key is the same as privKey's public key, discard otherwise
			if pubKey.Type() != (*privKey).PublicKey().Type() ||
				ssh.FingerprintSHA256(pubKey) != ssh.FingerprintSHA256((*privKey).PublicKey()) {
				return fmt.Errorf("ssh: public key authentication disabled by signature callback, mismatched public key")
			}
			switch pubKey.Type() {
			case ssh.KeyAlgoDSA:
				r, s := ParseDsaSignatureBlob(sig.Blob)
				// Offer the signature to the signature queue
				(*sigQueue).Offer(SampledDsaSignature{
					pubKeyType:        pubKey.Type(),
					pubKeyFingerprint: ssh.FingerprintSHA256(pubKey),
					signatureFormat:   sig.Format,
					signatureBlob:     sig.Blob,
					signedData:        signedData,
					r:                 r,
					s:                 s,
				})
			case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
				r, s := ParseEcdsaSignatureBlob(sig.Blob)
				// Offer the signature to the signature queue
				(*sigQueue).Offer(SampledEcdsaSignature{
					pubKeyType:        pubKey.Type(),
					pubKeyFingerprint: ssh.FingerprintSHA256(pubKey),
					signatureFormat:   sig.Format,
					signatureBlob:     sig.Blob,
					signedData:        signedData,
					r:                 r,
					s:                 s,
				})
			case ssh.KeyAlgoED25519:
				R, S, err := ParseEd25519SignatureBlob(sig.Blob)
				if err != nil {
					return fmt.Errorf("ssh: public key authentication disabled by signature callback, unable to parse ed25519 signature: %s", err)
				}
				// Offer the signature to the signature queue
				(*sigQueue).Offer(SampledEd25519Signature{
					pubKeyType:        pubKey.Type(),
					pubKeyFingerprint: ssh.FingerprintSHA256(pubKey),
					signatureFormat:   sig.Format,
					signatureBlob:     sig.Blob,
					signedData:        signedData,
					R:                 R,
					S:                 S,
				})
			default:
				// This should never happen given that we verify the public key fingerprint before offering the signature
				return fmt.Errorf("ssh: public key authentication disabled by signature callback, unsupported public key type: %s", pubKey.Type())
			}
			if noPartialSuccess {
				return fmt.Errorf("ssh: public key authentication restricted")
			}
			// Reject the signature to avoid successful authentication
			return &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
				PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					return &ssh.Permissions{}, nil
				},
			},
			}
		},
	}
	config.AddHostKey(hostKey)
	return &config, nil
}

// BuildClientCmd builds a command string from a template with placeholders for host and port.
// The placeholders are %host% and %port%.
func BuildClientCmd(cmdTemplate string, host string, port int) string {
	cmdTemplate = strings.ReplaceAll(cmdTemplate, "%host%", host)
	cmdTemplate = strings.ReplaceAll(cmdTemplate, "%port%", strconv.Itoa(port))
	return cmdTemplate
}

// ConnectClient runs a client command to connect to an SSH server.
func ConnectClient(clientCmd string) error {
	split := strings.Split(clientCmd, " ")
	cmd := exec.Command(split[0], split[1:]...)
	return cmd.Run()
}

// RunServer runs an SSH server on port 2200 + index.
func RunServer(index int, config *ssh.ServerConfig, timeout int, wg *sync.WaitGroup, finish <-chan bool) {
	defer wg.Done()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 2200 + index,
	})
	if err != nil {
		log.Printf("Error starting server in goroutine #%d: %s\n", index, err)
		return
	}
	defer listener.Close()
	for {
		select {
		case <-finish:
			return
		default:
			// Avoid blocking on Accept() when client goroutine shuts down by setting a deadline
			err := listener.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
			if err != nil {
				log.Printf("Unable to setup listener deadline in goroutine #%d: %s\n", index, err)
			}
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Error accepting connection from client in goroutine #%d: %s\n", index, err)
				continue
			}
			sshConn, _, _, err := ssh.NewServerConn(conn, config)
			if err != nil {
				_ = conn.Close()
				continue
			}
			_ = sshConn.Close()
			_ = conn.Close()
		}
	}
}

// LoadPrivateKeyFromFile loads a private key from file.
// The file must contain a private key in OpenSSH or PEM format.
func LoadPrivateKeyFromFile(path string) (interface{}, error) {
	privKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	privKeyParsed, err := ssh.ParseRawPrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}
	return privKeyParsed, nil
}

// ParseDsaSignatureBlob parses a signature blob as used by ssh.Signer.Sign and returns the r and s values as big.Int.
func ParseDsaSignatureBlob(blob []byte) (*big.Int, *big.Int) {
	r := new(big.Int)
	r.SetBytes(blob[:20])
	s := new(big.Int)
	s.SetBytes(blob[20:])
	return r, s
}

// ParseEcdsaSignatureBlob parses a signature blob as used by ssh.Signer.Sign and returns the r and s values as big.Int.
func ParseEcdsaSignatureBlob(blob []byte) (*big.Int, *big.Int) {
	rLength := binary.BigEndian.Uint32(blob[:4])
	sOffset := 4 + rLength
	sLength := binary.BigEndian.Uint32(blob[sOffset : sOffset+4])
	r := new(big.Int)
	r.SetBytes(blob[4 : 4+rLength])
	s := new(big.Int)
	s.SetBytes(blob[sOffset+4 : sOffset+4+sLength])
	return r, s
}

// ParseEd25519SignatureBlob parses a signature blob as an ed25519 signature and returns the R and S values as edwards25519.Point and edwards25519.Scalar.
func ParseEd25519SignatureBlob(blob []byte) (*edwards25519.Point, *edwards25519.Scalar, error) {
	R, err := edwards25519.NewIdentityPoint().SetBytes(blob[:32])
	if err != nil {
		return nil, nil, err
	}
	S, err := edwards25519.NewScalar().SetCanonicalBytes(blob[32:])
	if err != nil {
		return nil, nil, err
	}
	return R, S, nil
}

// RecoverDsaNonce recovers the nonce used to sign a message from a signature.
// The signature must be valid and the private key must be known.
// The signature algorithm must be of ssh.
// The signedData must be the data that was signed.
// Throws an error if the signature is invalid under the corresponding public key.
func RecoverDsaNonce(privKey *dsa.PrivateKey, signature *SampledDsaSignature) (*SampledDsaNonce, error) {
	hashFunc := HashFuncs[signature.signatureFormat]
	var digest []byte
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signature.signedData)
		digest = h.Sum(nil)
	} else {
		return nil, fmt.Errorf("unable to determine hashing algorithm for signature algorithm %s", signature.signatureFormat)
	}
	// Sanity check, signature should verify here
	valid := dsa.Verify(&privKey.PublicKey, digest, signature.r, signature.s)
	if !valid {
		// Signature might be computed over the pre-draft-07 variant of the signature payload
		// See https://author-tools.ietf.org/iddiff?url1=draft-ietf-secsh-userauth-06&url2=draft-ietf-secsh-userauth-07&difftype=--html
		// tl;dr: The session identifier is not encoded as a string but rather a byte array in this case
		h := hashFunc.New()
		h.Write(signature.signedData[4:])
		digest = h.Sum(nil)
		valid = dsa.Verify(&privKey.PublicKey, digest, signature.r, signature.s)
		if !valid {
			return nil, fmt.Errorf("invalid signature during sanity check")
		}
		// The signature is indeed a pre-draft-07 variant
		signature.signedData = signature.signedData[4:]
	}
	// Recover k := s^-1 * (z + rX) mod Q
	z := new(big.Int)
	z.SetBytes(digest)
	sInv := new(big.Int)
	sInv.ModInverse(signature.s, privKey.Q)
	k := new(big.Int)
	k.Mul(signature.r, privKey.X)
	k.Add(k, z)
	k.Mod(k, privKey.Q)
	k.Mul(k, sInv)
	k.Mod(k, privKey.Q)
	return &SampledDsaNonce{
		SampledDsaSignature: *signature,
		k:                   k,
	}, nil
}

// RecoverDsaNonces recovers nonces from a queue of signatures. The private key is loaded from a file.
// The function uses a number of workers to process the signatures concurrently. The number of workers should be
// equal to the number of CPU cores for optimal performance. The function returns the recovered nonces and the
// modulus of the private key for further analysis. Any signatures that are not ECDSA signatures are ignored.
func RecoverDsaNonces(sigQueue *queue.Queue, privKey *dsa.PrivateKey, workers int) []*SampledDsaNonce {
	log.Printf("> Recovering nonces from a total of %d signatures\n", (*sigQueue).Size())
	wg := sync.WaitGroup{}
	nonceQueue := queue.DefaultQueue()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !(*sigQueue).IsEmpty() {
				entry, _ := (*sigQueue).Poll().(SampledDsaSignature)
				k, err := RecoverDsaNonce(privKey, &entry)
				if err != nil {
					log.Println("error: unable to recover nonce from signature")
					continue
				}
				nonceQueue.Offer(k)
			}
		}()
	}
	wg.Wait()
	nonces := make([]*SampledDsaNonce, 0, nonceQueue.Size())
	for !nonceQueue.IsEmpty() {
		nonces = append(nonces, nonceQueue.Poll().(*SampledDsaNonce))
	}
	return nonces
}

// RecoverEcdsaNonce recovers the nonce used to sign a message from a signature.
// The signature must be valid and the private key must be known.
// The signature algorithm must be one of ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384 or ssh.KeyAlgoECDSA521.
// The signedData must be the data that was signed.
// Throws an error if the signature is invalid under the corresponding public key.
func RecoverEcdsaNonce(privKey *ecdsa.PrivateKey, signature *SampledEcdsaSignature) (*SampledEcdsaNonce, error) {
	hashFunc := HashFuncs[signature.signatureFormat]
	var digest []byte
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signature.signedData)
		digest = h.Sum(nil)
	} else {
		return nil, fmt.Errorf("unable to determine hashing algorithm for signature algorithm %s", signature.signatureFormat)
	}
	// Sanity check, signature should verify here
	valid := ecdsa.Verify(&privKey.PublicKey, digest, signature.r, signature.s)
	if !valid {
		// Signature might be computed over the pre-draft-07 variant of the signature payload
		// See https://author-tools.ietf.org/iddiff?url1=draft-ietf-secsh-userauth-06&url2=draft-ietf-secsh-userauth-07&difftype=--html
		// tl;dr: The session identifier is not encoded as a string but rather a byte array in this case
		h := hashFunc.New()
		h.Write(signature.signedData[4:])
		digest = h.Sum(nil)
		valid = ecdsa.Verify(&privKey.PublicKey, digest, signature.r, signature.s)
		if !valid {
			return nil, fmt.Errorf("invalid signature during sanity check")
		}
		// The signature is indeed a pre-draft-07 variant
		signature.signedData = signature.signedData[4:]
	}
	// Recover k := s^-1 * (z + rd) mod n
	z := new(big.Int)
	z.SetBytes(digest)
	sInv := new(big.Int)
	sInv.ModInverse(signature.s, privKey.Params().N)
	k := new(big.Int)
	k.Mul(signature.r, privKey.D)
	k.Add(k, z)
	k.Mod(k, privKey.Params().N)
	k.Mul(k, sInv)
	k.Mod(k, privKey.Params().N)
	return &SampledEcdsaNonce{
		SampledEcdsaSignature: *signature,
		k:                     k,
	}, nil
}

// RecoverEcdsaNonces recovers nonces from a queue of signatures. The private key is loaded from a file.
// The function uses a number of workers to process the signatures concurrently. The number of workers should be
// equal to the number of CPU cores for optimal performance. The function returns the recovered nonces and the
// modulus of the private key for further analysis. Any signatures that are not ECDSA signatures are ignored.
func RecoverEcdsaNonces(sigQueue *queue.Queue, privKey *ecdsa.PrivateKey, workers int) []*SampledEcdsaNonce {
	log.Printf("> Recovering nonces from a total of %d signatures\n", (*sigQueue).Size())
	wg := sync.WaitGroup{}
	nonceQueue := queue.DefaultQueue()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !(*sigQueue).IsEmpty() {
				entry, _ := (*sigQueue).Poll().(SampledEcdsaSignature)
				k, err := RecoverEcdsaNonce(privKey, &entry)
				if err != nil {
					log.Println("error: unable to recover nonce from signature")
					continue
				}
				nonceQueue.Offer(k)
			}
		}()
	}
	wg.Wait()
	nonces := make([]*SampledEcdsaNonce, 0, nonceQueue.Size())
	for !nonceQueue.IsEmpty() {
		nonces = append(nonces, nonceQueue.Poll().(*SampledEcdsaNonce))
	}
	return nonces
}

// RecoverEd25519Nonce recovers the nonce used to sign a message from a signature.
// The signature must be valid and the private key must be known.
// The signedData must be the data that was signed.
// Throws an error if the signature is invalid under the corresponding public key.
func RecoverEd25519Nonce(privKey *ed25519.PrivateKey, signature *SampledEd25519Signature) (*SampledEd25519Nonce, error) {
	// Sanity check, signature should verify here
	valid := ed25519.Verify(privKey.Public().(ed25519.PublicKey), signature.signedData, signature.signatureBlob)
	if !valid {
		// Signature might be computed over the pre-draft-07 variant of the signature payload
		// See https://author-tools.ietf.org/iddiff?url1=draft-ietf-secsh-userauth-06&url2=draft-ietf-secsh-userauth-07&difftype=--html
		// tl;dr: The session identifier is not encoded as a string but rather a byte array in this case
		valid := ed25519.Verify(privKey.Public().(ed25519.PublicKey), signature.signedData[4:], signature.signatureBlob)
		if !valid {
			return nil, fmt.Errorf("invalid signature during sanity check")
		}
		// The signature is indeed a pre-draft-07 variant
		signature.signedData = signature.signedData[4:]
	}

	// Hash the 32-byte private key using SHA-512, storing the digest in
	// a 64-octet large buffer, denoted h.  Only the lower 32 bytes are
	// used for generating the public key.
	seed := (*privKey)[:32]
	hashFunc := sha512.New()
	hashFunc.Write(seed)
	h := hashFunc.Sum(nil)

	sBytes := h[:32]
	// Prune the buffer: The lowest three bits of the first octet are
	// cleared, the highest bit of the last octet is cleared, and the
	// second highest bit of the last octet is set.

	// Interpret the buffer as the little-endian integer, forming a
	// secret scalar s.
	s, err := edwards25519.NewScalar().SetBytesWithClamping(sBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to set scalar from bytes: %s", err)
	}

	// Compute SHA512(dom2(F, C) || R || A || PH(M)), ...
	hashFunc.Reset()
	hashFunc.Write(signature.R.Bytes())
	hashFunc.Write((*privKey)[32:])
	hashFunc.Write(signature.signedData)
	// ... and interpret the 64-octet digest as a little-endian integer k
	kBytes := hashFunc.Sum(nil)
	k, err := edwards25519.NewScalar().SetUniformBytes(kBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to set scalar from bytes: %s", err)
	}

	// S = (r + k * s) mod L
	// Therefore, recover r = (S - k * s) mod L
	temp := edwards25519.NewScalar().Multiply(k, s)
	r := edwards25519.NewScalar().Subtract(signature.S, temp)

	// Sanity check R = [r]B?
	Rsanity := edwards25519.NewGeneratorPoint().ScalarBaseMult(r)
	if Rsanity.Equal(signature.R) != 1 {
		return nil, fmt.Errorf("invalid R value during sanity check")
	}

	return &SampledEd25519Nonce{
		SampledEd25519Signature: *signature,
		r:                       r,
	}, nil
}

// RecoverEd25519Nonces recovers nonces from a queue of signatures. The private key is loaded from a file.
// The function uses a number of workers to process the signatures concurrently. The number of workers should be
// equal to the number of CPU cores for optimal performance. The function returns the recovered nonces and the
// modulus of the private key for further analysis. Any signatures that are not ED25519 signatures are ignored.
func RecoverEd25519Nonces(sigQueue *queue.Queue, privKey *ed25519.PrivateKey, workers int) []*SampledEd25519Nonce {
	log.Printf("> Recovering nonces from a total of %d signatures\n", (*sigQueue).Size())
	wg := sync.WaitGroup{}
	nonceQueue := queue.DefaultQueue()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !(*sigQueue).IsEmpty() {
				entry, _ := (*sigQueue).Poll().(SampledEd25519Signature)
				k, err := RecoverEd25519Nonce(privKey, &entry)
				if err != nil {
					log.Printf("error: unable to recover nonce from signature: %s\n", err)
					continue
				}
				nonceQueue.Offer(k)
			}
		}()
	}
	wg.Wait()
	nonces := make([]*SampledEd25519Nonce, 0, nonceQueue.Size())
	for !nonceQueue.IsEmpty() {
		nonces = append(nonces, nonceQueue.Poll().(*SampledEd25519Nonce))
	}
	return nonces
}

// SampleAgentSignatures loads a private key into an SSH agent, generates signatures, and queues them for analysis.
// Parameters:
// privKey: The private key to be added to the SSH agent.
// sigQueue: A queue to hold generated signature data.
// signatureCount: The number of signatures to generate.
// reuseData: Whether to reuse the same data for signing or generate new data for each signature.
// Returns an error if the operation fails at any point.
func SampleAgentSignatures(signatureCount int, reuseData bool, sigQueue *queue.Queue, privKey interface{}) error {
	socket := os.Getenv("SSH_AUTH_SOCK")
	log.Printf("> SSH_AUTH_SOCK=%s", socket)
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("> Failed to open SSH_AUTH_SOCK: %v", err)
	}
	agentClient := agent.NewClient(conn)
	sampleKey := agent.AddedKey{PrivateKey: privKey}
	log.Printf("> Loading private key into SSH agent for testing")
	err = agentClient.Add(sampleKey)
	if err != nil {
		log.Printf("> Failed to add private key to SSH agent, continuing anyway: %v", err)
	}
	var pubKey ssh.PublicKey
	switch privKey.(type) {
	case *dsa.PrivateKey:
		pubKey, err = ssh.NewPublicKey(&privKey.(*dsa.PrivateKey).PublicKey)
	case *ecdsa.PrivateKey:
		pubKey, err = ssh.NewPublicKey(&privKey.(*ecdsa.PrivateKey).PublicKey)
	case *ed25519.PrivateKey:
		keyBytes := []byte(*privKey.(*ed25519.PrivateKey))
		pkBytes := ed25519.PublicKey(keyBytes[32:])
		pubKey, err = ssh.NewPublicKey(pkBytes)
	}
	if err != nil {
		log.Printf("> Failed to generate matching public key: %v", err)
		return err
	}
	var tbs []byte
	for i := 0; i < signatureCount; i++ {
		if i == 0 || !reuseData {
			// Generate 32 random bytes for testing
			tbs = make([]byte, 32)
			n, err := rand.Read(tbs)
			if n < 32 || err != nil {
				log.Printf("> Failed to generate random data: %v", err)
				return err
			}
		}
		sig, err := agentClient.Sign(pubKey, tbs)
		if err != nil {
			log.Printf("> Failed to generate signature #%v for determinism analysis: %v", i, err)
			return err
		}
		switch pubKey.Type() {
		case ssh.KeyAlgoDSA:
			r, s := ParseDsaSignatureBlob(sig.Blob)
			// Offer the signature to the signature queue
			(*sigQueue).Offer(SampledDsaSignature{
				pubKeyType:        pubKey.Type(),
				pubKeyFingerprint: ssh.FingerprintSHA256(pubKey),
				signatureFormat:   sig.Format,
				signatureBlob:     sig.Blob,
				signedData:        tbs,
				r:                 r,
				s:                 s,
			})
		case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
			r, s := ParseEcdsaSignatureBlob(sig.Blob)
			// Offer the signature to the signature queue
			(*sigQueue).Offer(SampledEcdsaSignature{
				pubKeyType:        pubKey.Type(),
				pubKeyFingerprint: ssh.FingerprintSHA256(pubKey),
				signatureFormat:   sig.Format,
				signatureBlob:     sig.Blob,
				signedData:        tbs,
				r:                 r,
				s:                 s,
			})
		case ssh.KeyAlgoED25519:
			R, S, err := ParseEd25519SignatureBlob(sig.Blob)
			if err != nil {
				return fmt.Errorf("ssh: public key authentication disabled by signature callback, unable to parse ed25519 signature: %s", err)
			}
			// Offer the signature to the signature queue
			(*sigQueue).Offer(SampledEd25519Signature{
				pubKeyType:        pubKey.Type(),
				pubKeyFingerprint: ssh.FingerprintSHA256(pubKey),
				signatureFormat:   sig.Format,
				signatureBlob:     sig.Blob,
				signedData:        tbs,
				R:                 R,
				S:                 S,
			})
		default:
			// This should never happen given that we verify the public key fingerprint before offering the signature
			return fmt.Errorf("ssh: public key authentication disabled by signature callback, unsupported public key type: %s", pubKey.Type())
		}
	}
	err = agentClient.Remove(pubKey)
	if err != nil {
		log.Printf("> Failed to remove public from SSH agent after signature generation, continuing anyway: %v", err)
	}
	return nil
}
