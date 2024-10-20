// srp.go - golang implementation of SRP-6a
//
// Copyright 2013-2017 Sudhi Herle <sudhi.herle-at-gmail-dot-com>
// License: MIT
//

// Package srp implements SRP-6a per [1]. It uses the standard library
// and the golang extended library and nothing else.
//
// This implementation is accurate as of Aug 2012 edition of the SRP
// specification [1].
//
// To verify that the client has generated the same key "K", the client sends
// "M" -- a hash of all the data it has and it received from the server. To
// validate that the server also has the same value, it requires the server to send
// its own proof. In the SRP paper [1], the authors use:
//
//	M = H(H(N) xor H(g), H(I), s, A, B, K)
//	M' = H(A, M, K)
//
// We use a simpler construction:
//
//	M = H(K, A, B, I, s, N, g)
//	M' = H(M, K)
//
// In this implementation:
//
//	H  = BLAKE2()
//	k  = H(N, g)
//	x  = H(s, I, P)
//	I  = anonymized form of user identity (BLAKE2 of value sent by client)
//	P  = hashed password (expands short passwords)
//
// Per RFC-5054, we adopt the following padding convention:
//
//	k = H(N, pad(g))
//	u = H(pad(A), pad(B))
//
// References:
//
//	[1] http://srp.stanford.edu/design.html
//	[2] http://srp.stanford.edu/
package srp

// Implementation Notes
// ---------------------
//
// Conventions
//   N    A large safe prime (N = 2q+1, where q is prime)
//        All arithmetic is done modulo N.
//   g    A generator modulo N
//   k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
//   s    User's salt
//   I    Username
//   p    Cleartext Password
//   H()  One-way hash function
//   ^    (Modular) Exponentiation
//   u    Random scrambling parameter
//   a,b  Secret ephemeral values
//   A,B  Public ephemeral values
//   x    Private key (derived from p and s)
//   v    Password verifier
//
// The host stores passwords using the following formula:
//
//   s = randomsalt()          (same length as N)
//   I = H(I)
//   p = H(p)                  (hash/expand I & p)
//   t = H(I, ":", p)
//   x = H(s, t)
//   v = g^x                   (computes password verifier)
//
// The host then keeps {I, s, v} in its password database.
//
// The authentication protocol itself goes as follows:
//
//  Client                       Server
//  --------------               ----------------
//  I, p = < user input >
//  I = H(I)
//  p = H(p)
//  a = random()
//  A = g^a % N
//                 I, A -->
//                               s, v = lookup(I)
//                               b = random()
//                               B = (kv + g^b) % N
//                               u = H(A, B)
//                               S = ((A * v^u) ^ b) % N
//                               K = H(S)
//                               M' = H(K, A, B, I, s, N, g)
//                  <-- s, B
//  u = H(A, B)
//  x = H(s, p)
//  S = ((B - k (g^x)) ^ (a + ux)) % N
//  K = H(S)
//  M = H(K, A, B, I, s, N, g)
//
//		    M -->
//				M must be equal to M'
//				Z = H(M, K)
//		    <-- Z
//  Z' = H(M, K)
//  Z' must equal Z
// -----------------------------------------------------------------
// When the server receives <I, A>, it can compute everything: shared key
// and proof-of-generation (M'). The shared key is "K".
//
// To verify that the client has generated the same key "K", the client sends
// "M" -- a hash of all the data it has and it received from the server. To
// validate that the server also has the same value, it requires the server to send
// its own proof. We use a simpler construction:
//
//     M = H(K, A, B, I, s, N, g)
//     M' = H(M, K)
//
// Client & Server also employ the following safeguards:
//
//  1. The user will abort if he receives B == 0 (mod N) or u == 0.
//  2. The host will abort if it detects that A == 0 (mod N).
//  3. The user must show his proof of K first. If the server detects that the
//     user's proof is incorrect, it must abort without showing its own proof of K.

/* UPDATED TO WORK WITH APPLE'S SRP IMPLEMENTATION by blacktop */

import (
	"bytes"
	"crypto"
	CR "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	// stdlib has an enum for Blake2b_256; this lib registers itself against it.

	_ "golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/pbkdf2"
)

// SRP represents an environment for the client and server to share certain properties;
// notably the hash function and prime-field size.  The default hash function is
// Blake2b-256. Any valid hash function as documented in "crypto" can be used.
// There are two ways for creating an SRP environment:
//
//	New()
//	NewWithHash()
type SRP struct {
	h  crypto.Hash
	pf *primeField
	a  *big.Int
	A  *big.Int
}

// FieldSize returns this instance's prime-field size in bits
func (s *SRP) FieldSize() int {
	return s.pf.n * 8
}

// New creates a new SRP environment using a 'bits' sized prime-field for
// use by SRP clients and Servers.The default hash function is Blake-2b-256.
func New(bits int) (*SRP, error) {
	return NewWithHash(crypto.BLAKE2b_256, bits)
}

// NewWithHash creates a new SRP environment using the hash function 'h' and
// 'bits' sized prime-field size.
func NewWithHash(h crypto.Hash, bits int) (*SRP, error) {

	pf, err := findPrimeField(bits)
	if err != nil {
		return nil, err
	}

	s := &SRP{
		h:  h,
		pf: pf,
		a:  randBigInt(pf.n * 8),
	}

	s.A = big.NewInt(0).Exp(pf.g, s.a, pf.N)

	return s, nil
}

// ServerBegin processes the first message from an SRP client and returns a decoded
// identity string and client public key. The caller is expected to use the identity
// to lookup durable storage and find the corresponding encoded Verifier. This verifier
// is given to MakeSRPVerifier() to create an instance of SRP and Verifier.
func ServerBegin(creds string) (string, *big.Int, error) {
	v := strings.Split(creds, ":")
	if len(v) != 2 {
		return "", nil, fmt.Errorf("srp: invalid client public key")
	}

	//fmt.Printf("v0: %s\nv1: %s\n", v[0], v[1])

	A, ok := big.NewInt(0).SetString(v[1], 16)
	if !ok {
		return "", nil, fmt.Errorf("srp: invalid client public key A")
	}

	return v[0], A, nil
}

// Verifier represents password verifier that resides on an SRP server.
type Verifier struct {
	i  []byte      // hashed identity
	s  []byte      // random salt (same size as prime field)
	v  []byte      // password verifier
	h  crypto.Hash // hash algo used for building v
	pf *primeField // the prime field (g, N)
}

// Verifier generates a password verifier for user I and passphrase p
// in the environment 's'. It returns an instance of Verifier that holds the
// parameters needed for a future authentication.
func (s *SRP) Verifier(I, p []byte) (*Verifier, error) {
	ih := s.hashbyte(I)
	ph := s.hashbyte(p)
	pf := s.pf
	salt := randbytes(pf.n)
	x := s.hashint(ih, ph, salt)
	r := big.NewInt(0).Exp(pf.g, x, pf.N)

	v := &Verifier{
		i:  ih,
		s:  salt,
		v:  r.Bytes(),
		h:  s.h,
		pf: pf,
	}

	return v, nil
}

// MakeSRPVerifier decodes the encoded verifier into an SRP environment
// and Verifier instance. 'b' is an encoded verifier string previously
// returned by Verifier.Encode().  A caller of this function uses the identity
// provided by the SRP Client to lookup some DB to find the corresponding encoded
// verifier string; this encoded data contains enough information to create a
// valid SRP instance and Verifier instance.
func MakeSRPVerifier(b string) (*SRP, *Verifier, error) {
	v := strings.Split(b, ":")
	if len(v) != 7 {
		return nil, nil, fmt.Errorf("verifier: malformed fields exp 5, saw %d", len(v))
	}

	ss := v[0]
	sz, err := strconv.Atoi(ss)
	if err != nil || sz <= 0 {
		return nil, nil, fmt.Errorf("verifier: malformed field size %s", ss)
	}

	ss = v[1]
	p, ok := big.NewInt(0).SetString(ss, 16)
	if !ok {
		return nil, nil, fmt.Errorf("verifier: malformed prime %s", ss)
	}

	ss = v[2]
	g, ok := big.NewInt(0).SetString(ss, 16)
	if !ok {
		return nil, nil, fmt.Errorf("verifier: malformed generator %s", ss)
	}

	ss = v[3]
	h, err := strconv.Atoi(ss)
	if err != nil || h <= 0 {
		return nil, nil, fmt.Errorf("verifier: malformed hash type %s", ss)
	}

	hf := crypto.Hash(h)
	if !hf.Available() {
		return nil, nil, fmt.Errorf("verifier: hash algorithm %d unavailable", h)
	}

	ss = v[4]
	i, err := hex.DecodeString(ss)
	if err != nil {
		return nil, nil, fmt.Errorf("verifier: invalid identity: %s", ss)
	}

	ss = v[5]
	s, err := hex.DecodeString(ss)
	if err != nil {
		return nil, nil, fmt.Errorf("verifier: invalid salt: %s", ss)
	}

	ss = v[6]
	vx, err := hex.DecodeString(ss)
	if err != nil {
		return nil, nil, fmt.Errorf("verifier: invalid verifier: %s", ss)
	}

	sr := &SRP{
		h: hf,
		pf: &primeField{
			n: sz,
			N: p,
			g: g,
		},
	}

	vf := &Verifier{
		i:  i,
		s:  s,
		v:  vx,
		h:  hf,
		pf: sr.pf,
	}

	return sr, vf, nil
}

// Encode the verifier into a portable format - returns a tuple
// <Identity, Verifier> as portable strings. The caller can store
// the Verifier against the Identity in non-volatile storage.
// An SRP client will supply Identity and its public key - whereupon,
// an SRP server will use the Identity as a key to lookup
// the rest of the encoded verifier data.
func (v *Verifier) Encode() (string, string) {
	var b bytes.Buffer

	ih := hex.EncodeToString(v.i)

	b.WriteString(fmt.Sprintf("%d:", v.pf.n))
	b.WriteString(fmt.Sprintf("%x:", v.pf.N))
	b.WriteString(fmt.Sprintf("%x:", v.pf.g))
	b.WriteString(fmt.Sprintf("%d:", int(v.h)))
	b.WriteString(ih)
	b.WriteByte(':')
	b.WriteString(hex.EncodeToString(v.s))
	b.WriteByte(':')
	b.WriteString(hex.EncodeToString(v.v))

	return ih, b.String()
}

// Client represents an SRP client instance
type Client struct {
	s  *SRP
	i  []byte
	p  []byte
	a  *big.Int
	xA *big.Int
	k  *big.Int

	xK   []byte
	xM   []byte
	xAMK []byte
}

// NewClient constructs an SRP client instance.
func (s *SRP) NewClient(I, p, salt []byte, iter int) (*Client, error) {
	digest := sha256.New() // TODO: should this be s.h.New()?
	if _, err := digest.Write(p); err != nil {
		return nil, fmt.Errorf("srp: failed to hash password")
	}
	c := &Client{
		s: s,
		i: s.hashbyte(I),
		p: pbkdf2.Key(digest.Sum(nil), salt, iter, 32, sha256.New),
		a: s.a,
		k: s.hashint(s.pf.N.Bytes(), pad(s.pf.g, s.pf.n)),
	}
	c.xA = s.A
	//fmt.Printf("Client %d:\n\tA=%x\n\tk=%x", bits, c.xA, c.k)
	return c, nil
}

// Credentials returns client public credentials to send to server
// Send <I, A> to server
func (c *Client) Credentials() string {
	var b bytes.Buffer

	b.WriteString(hex.EncodeToString(c.i))
	b.WriteByte(':')
	b.WriteString(hex.EncodeToString(c.xA.Bytes()))
	return b.String()
}

// Generate validates the server public credentials and generate session key
// Return the mutual authenticator.
// NB: We don't send leak any information in error messages.
func (c *Client) Generate(salt, b []byte) ([]byte, []byte, error) {
	pf := c.s.pf

	B := big.NewInt(0).SetBytes(b)
	if B.Cmp(big.NewInt(0)) == 0 {
		return nil, nil, fmt.Errorf("srp: invalid server public key")
	}

	u := c.s.hashint(pad(c.xA, pf.n), pad(B, pf.n))
	if u.Cmp(big.NewInt(0)) == 0 {
		return nil, nil, fmt.Errorf("srp: invalid server public key")
	}

	// S := ((B - kg^x) ^ (a + ux)) % N

	x := c.s.hashint(salt, c.s.hashbyte([]byte(":"), c.p))
	t0 := big.NewInt(0).Exp(pf.g, x, pf.N)
	t0 = t0.Mul(t0, c.k)

	t1 := big.NewInt(0).Sub(B, t0)
	t2 := big.NewInt(0).Add(c.a, big.NewInt(0).Mul(u, x))
	S := big.NewInt(0).Exp(t1, t2, pf.N)

	c.xK = c.s.hashbyte(S.Bytes())
	//	M = H(H(N) xor H(g), H(I), s, A, B, K)
	c.xM = c.s.hashbyte(
		xorBytes(
			c.s.hashbyte(pf.N.Bytes()),
			c.s.hashbyte(pad(pf.g, pf.n)),
		),
		c.i,
		salt, c.xA.Bytes(), B.Bytes(), c.xK)
	//	M' = H(A, M, K)
	c.xAMK = c.s.hashbyte(c.xA.Bytes(), c.xM, c.xK)

	return c.xM, c.xAMK, nil
}

// ServerOk takes a 'proof' offered by the server and verifies that it is valid.
// i.e., we should compute the same hash() on M that the server did.
func (c *Client) ServerOk(proof string) bool {
	h := c.s.hashbyte(c.xK, c.xM)
	myh := hex.EncodeToString(h)

	return subtle.ConstantTimeCompare([]byte(myh), []byte(proof)) == 1
}

// RawKey returns the raw key computed as part of the protocol
func (c *Client) RawKey() []byte {
	return c.xK
}

// String represents the client parameters as a string value
func (c *Client) String() string {
	pf := c.s.pf
	return fmt.Sprintf("<client> g=%d, N=%x\n I=%x\n A=%x\n K=%x\n",
		pf.g, pf.N, c.i, c.xA, c.xK)
}

// hash byte stream and return as bytes
func (s *SRP) hashbyte(a ...[]byte) []byte {
	h := s.h.New()
	for _, z := range a {
		h.Write(z)
	}
	return h.Sum(nil)
}

// hash a number of byte strings and return the resulting hash as
// bigint
func (s *SRP) hashint(a ...[]byte) *big.Int {
	i := big.NewInt(0)
	b := s.hashbyte(a...)
	i.SetBytes(b)
	return i
}

func atoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("srp init: can't parse int %s", s))
	}
	return i
}

func atobi(s string, base int) *big.Int {
	i, ok := big.NewInt(0).SetString(s, base)
	if !ok {
		panic(fmt.Sprintf("srp init: can't parse bigint |%s|", s))
	}
	return i
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil //, fmt.Errorf("slices must be of equal length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result //, nil
}

// pad x to n bytes if needed
func pad(x *big.Int, n int) []byte {
	b := x.Bytes()
	if len(b) < n {
		z := n - len(b)
		p := make([]byte, n)
		for i := 0; i < z; i++ {
			p[i] = 0
		}

		copy(p[z:], b)
		b = p
	}
	return b
}

// Return n bytes of random  bytes. Uses cryptographically strong
// random generator
func randbytes(n int) []byte {
	b := make([]byte, n)
	_, err := io.ReadFull(CR.Reader, b)
	if err != nil {
		panic("Random source is broken!")
	}
	return b
}

// Generate and return a bigInt 'bits' bits in length
func randBigInt(bits int) *big.Int {
	n := bits / 8
	if (bits % 8) != 0 {
		n += 1
	}
	b := randbytes(n)
	r := big.NewInt(0).SetBytes(b)
	return r
}

// Make a new prime field (safe prime & generator) that is 'nbits' long
// Return prime p, generator g
func NewPrimeField(nbits int) (p, g *big.Int, err error) {
	var pf *primeField

	if nbits < 0 {
		return nil, nil, fmt.Errorf("srp: bad field size %d", nbits)
	} else if nbits == 0 {
		nbits = 2048
	}

	pf, err = newPrimeField(nbits)
	if err != nil {
		return nil, nil, err
	}

	return pf.N, pf.g, nil
}

// Make a new prime field where the prime is 'nbits' long
// This function is not used currently. In the future, one can use this to create
// an SRP Environment where the prime field (p, g) is generated at runtime for maximum
// security.
func newPrimeField(nbits int) (*primeField, error) {

	for i := 0; i < 100; i++ {
		p, err := safePrime(nbits)
		if err != nil {
			return nil, err
		}

		for _, g0 := range simplePrimes {
			g := big.NewInt(g0)
			if isGenerator(g, p) {
				pf := &primeField{
					g: g,
					N: p,
					n: nbits / 8,
				}
				return pf, nil
			}
		}
	}
	return nil, fmt.Errorf("srp: can't find generator after 100 tries")
}

// Find a pre-generated safe-prime and its generator from our list below.
// In the future, we can use some other external eternal source of such things.
// NB: Generating large safe-primes is computationally taxing! It is best done offline.
func findPrimeField(bits int) (*primeField, error) {

	switch {
	case bits < 0:
		return nil, fmt.Errorf("srp: invalid prime-field size %d", bits)

	case bits == 0:
		bits = 2048
		fallthrough

	default:
		if pf, ok := pflist[bits]; ok {
			return pf, nil
		}
		return nil, fmt.Errorf("srp: invalid prime-field size %d", bits)
	}
}

// build the database of prime fields and generators
func init() {

	one = big.NewInt(1)
	pflist = make(map[int]*primeField)
	lines := strings.Split(pflistStr, "\n")
	for _, s := range lines {
		v := strings.Split(s, ":")
		b := atoi(v[0])

		pf := &primeField{
			g: atobi(v[1], 10),
			N: atobi(v[2], 0),
			n: b / 8,
		}
		if big.NewInt(0).Cmp(pf.N) == 0 {
			panic(fmt.Sprintf("srp init: N (%s) is zero", v[2]))
		}
		pflist[b] = pf
	}
}

// Map of bits to <g, N> tuple
const pflistStr = `1024:2:0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
1536:2:0x9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB
2048:2:0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73
3072:5:0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
4096:5:0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
6144:5:0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF
8192:19:0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF`

// First 100 primes
var simplePrimes = []int64{
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
	67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
	139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
	223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
	293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
	383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
	463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
}

type primeField struct {
	g *big.Int
	N *big.Int
	n int // size of N in bytes
}

// prime field list - mapped by bit size; initialized via init() above.
var pflist map[int]*primeField
var one *big.Int

// vim: noexpandtab:sw=8:ts=8:tw=92:
