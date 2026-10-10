package srp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

const (
	grandSlamSecretBytes      = 32
	grandSlamMaxCredential    = 4096
	grandSlamMaxSalt          = 1024
	grandSlamMaxIterations    = 1_000_000
	grandSlamMaxPublicKeySize = 257
)

// GrandSlam is Apple's SHA-256 SRP client for the GrandSlam authentication
// service. Its password derivation and public-value hashing differ from IDMSA.
type GrandSlam struct {
	s *SRP
}

// GrandSlamProof contains the client proof, expected server proof, and session
// key calculated from one GrandSlam challenge.
type GrandSlamProof struct {
	m1  []byte
	m2  []byte
	key []byte
}

// NewGrandSlam creates a client with a fresh 256-bit private ephemeral.
func NewGrandSlam() (*GrandSlam, error) {
	pf, err := findPrimeField(2048)
	if err != nil {
		return nil, err
	}

	var secret [grandSlamSecretBytes]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, fmt.Errorf("srp: generate GrandSlam secret: %w", err)
	}
	defer clear(secret[:])

	s := &SRP{h: crypto.SHA256, pf: pf, a: new(big.Int).SetBytes(secret[:])}
	if s.a.Sign() == 0 {
		return nil, errors.New("srp: generated an invalid GrandSlam secret")
	}
	s.A = new(big.Int).Exp(pf.g, s.a, pf.N)
	return &GrandSlam{s: s}, nil
}

// PublicKey returns the minimal big-endian encoding of the client public key A.
func (g *GrandSlam) PublicKey() []byte {
	return g.s.A.Bytes()
}

// Complete processes a GrandSlam challenge. GSA hashes minimal A, B, and S
// encodings; only the group generator is padded to the modulus width.
func (g *GrandSlam) Complete(username, password string, salt, serverPublic []byte, iterations int, protocol PasswordProtocol) (*GrandSlamProof, error) {
	if len(username) > grandSlamMaxCredential {
		return nil, errors.New("srp: GrandSlam username exceeds limit")
	}
	if len(serverPublic) == 0 || len(serverPublic) > grandSlamMaxPublicKeySize {
		return nil, errors.New("srp: invalid GrandSlam server public key length")
	}

	s := g.s
	pf := s.pf
	B := new(big.Int).SetBytes(serverPublic)
	if new(big.Int).Mod(B, pf.N).Sign() == 0 {
		return nil, errors.New("srp: invalid GrandSlam server public key")
	}

	aPublic, bPublic := s.A.Bytes(), B.Bytes()
	u := s.hashint(aPublic, bPublic)
	if u.Sign() == 0 {
		return nil, errors.New("srp: invalid GrandSlam scrambling parameter")
	}

	derived, err := deriveGrandSlamPassword(protocol, password, salt, iterations)
	if err != nil {
		return nil, err
	}
	defer clear(derived)

	k := s.hashint(pf.N.Bytes(), pad(pf.g, pf.n))
	x := s.hashint(salt, s.hashbyte([]byte(":"), derived))
	verifier := new(big.Int).Exp(pf.g, x, pf.N)
	base := new(big.Int).Sub(B, new(big.Int).Mul(k, verifier))
	exponent := new(big.Int).Add(s.a, new(big.Int).Mul(u, x))
	premaster := new(big.Int).Exp(base, exponent, pf.N)
	premasterBytes := premaster.Bytes()
	if len(premasterBytes) == 0 {
		// Rust's num_bigint encodes zero as one zero byte.
		premasterBytes = []byte{0}
	}
	key := s.hashbyte(premasterBytes)
	m1 := s.hashbyte(
		xorBytes(s.hashbyte(pf.N.Bytes()), s.hashbyte(pad(pf.g, pf.n))),
		s.hashbyte([]byte(username)), salt, aPublic, bPublic, key,
	)
	m2 := s.hashbyte(aPublic, m1, key)
	return &GrandSlamProof{m1: m1, m2: m2, key: key}, nil
}

// Proof returns the client proof M1 to send to the server.
func (p *GrandSlamProof) Proof() []byte { return bytes.Clone(p.m1) }

// SessionKey returns the shared key used to decrypt the server-provided data.
func (p *GrandSlamProof) SessionKey() []byte { return bytes.Clone(p.key) }

// VerifyServer checks the server's M2 reply in constant time.
func (p *GrandSlamProof) VerifyServer(reply []byte) error {
	if p == nil || len(p.m2) != sha256.Size || subtle.ConstantTimeCompare(p.m2, reply) != 1 {
		return errors.New("srp: GrandSlam server proof verification failed")
	}
	return nil
}

func deriveGrandSlamPassword(protocol PasswordProtocol, password string, salt []byte, iterations int) ([]byte, error) {
	if len(password) > grandSlamMaxCredential {
		return nil, errors.New("srp: GrandSlam password exceeds limit")
	}
	if len(salt) > grandSlamMaxSalt {
		return nil, errors.New("srp: GrandSlam salt exceeds limit")
	}
	if iterations < 1 || iterations > grandSlamMaxIterations {
		return nil, errors.New("srp: GrandSlam iteration count is outside limits")
	}
	if protocol != ProtocolS2K && protocol != ProtocolS2KFO {
		return nil, errors.New("srp: unsupported GrandSlam password protocol")
	}

	digest := sha256.Sum256([]byte(password))
	derived := pbkdf2.Key(digest[:], salt, iterations, sha256.Size, sha256.New)
	if protocol == ProtocolS2KFO {
		encoded := make([]byte, hex.EncodedLen(len(derived)))
		hex.Encode(encoded, derived)
		clear(derived)
		return encoded, nil
	}
	return derived, nil
}
