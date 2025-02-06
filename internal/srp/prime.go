// prime.go - Generate safe primes
//
// Copyright 2013-2017 Sudhi Herle <sudhi.herle-at-gmail-dot-com>
// License: MIT

package srp

/* UPDATED TO WORK WITH APPLE'S SRP IMPLEMENTATION by blacktop */

import (
	"crypto/rand"
	"math/big"
)

// safePrime generates a safe prime; i.e., a prime 'p' such that 2p+1 is also prime.
func safePrime(bits int) (*big.Int, error) {

	a := new(big.Int)
	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}

		// 2p+1
		a = a.Lsh(p, 1)
		a = a.Add(a, one)
		if a.ProbablyPrime(20) {
			return a, nil
		}
	}

	// never reached
	return nil, nil
}

// Return true if g is a generator for safe prime p
//
// From Cryptography Theory & Practive, Stinson and Paterson (Th. 6.8 pp 196):
//
//	If p > 2 is a prime and g is in Zp*, then
//	g is a primitive element modulo p iff g ^ (p-1)/q != 1 (mod p)
//	for all primes q such that q divides (p-1).
//
// "Primitive Element" and "Generator" are the same thing in Number Theory.
//
// Code below added as a result of bug pointed out by Dharmalingam G. (May 2019)
func isGenerator(g, p *big.Int) bool {
	p1 := big.NewInt(0).Sub(p, one)
	q := big.NewInt(0).Rsh(p1, 1) // q = p-1/2 = ((p-1) >> 1)

	// p is a safe prime. i.e., it is of the form 2q+1 where q is prime.
	//
	// => p-1 = 2q, where q is a prime.
	//
	// All factors of p-1 are: {2, q, 2q}
	//
	// So, our check really comes down to:
	//   1) g ^ (p-1/2q) != 1 mod p
	//		=> g ^ (2q/2q) != 1 mod p
	//		=> g != 1 mod p
	//	    Trivial case. We ignore this.
	//
	//   2) g ^ (p-1/2) != 1 mod p
	//      => g ^ (2q/2) != 1 mod p
	//      => g ^ q != 1 mod p
	//
	//   3) g ^ (p-1/q) != 1 mod p
	//      => g ^ (2q/q) != 1 mod p
	//      => g ^ 2 != 1 mod p
	//

	// g ^ 2 mod p
	if !ok(g, big.NewInt(0).Lsh(one, 1), p) {
		return false
	}

	// g ^ q mod p
	if !ok(g, q, p) {
		return false
	}

	return true
}

func ok(g, x *big.Int, p *big.Int) bool {
	z := big.NewInt(0).Exp(g, x, p)
	// the expmod should NOT be 1
	return z.Cmp(one) != 0
}

// vim: noexpandtab:sw=8:ts=8:tw=92:
