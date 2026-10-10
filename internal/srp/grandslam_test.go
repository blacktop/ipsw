package srp

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

const (
	grandSlamTestUsername = "synthetic@example.test"
	grandSlamTestPassword = "synthetic-password-Δ"
	grandSlamTestSalt     = "00112233445566778899aabbccddeeff"
	grandSlamTestRounds   = 17
)

func TestGrandSlamPasswordVectors(t *testing.T) {
	// Independently computed with Python hashlib.pbkdf2_hmac. s2k_fo
	// supplies sha256(password).hexdigest().encode() as its password.
	salt := decodeGrandSlamHex(t, grandSlamTestSalt)
	for _, tc := range []struct {
		protocol PasswordProtocol
		want     []byte
	}{
		{ProtocolS2K, decodeGrandSlamHex(t, "7e45a9b84ecc792912c1eebbefb2ba11ed372d6fc501a7c2f096b1c7866a6419")},
		{ProtocolS2KFO, decodeGrandSlamHex(t, "50278ff04f769bcd5230ef32224212eb98224c5142a50ef78fd98372201519a0")},
	} {
		t.Run(string(tc.protocol), func(t *testing.T) {
			got, err := deriveGrandSlamPassword(tc.protocol, grandSlamTestPassword, salt, grandSlamTestRounds)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("derived password = %x, want %x", got, tc.want)
			}
		})
	}
}

func TestGrandSlamShortPublicValueVectors(t *testing.T) {
	// Python hashlib and modular pow computed these independently from the
	// GrandSlam formulas. a=1 produces A=2, and B=3, so using the
	// IDMSA padded scrambling hash changes every expected result.
	for _, tc := range []struct {
		protocol PasswordProtocol
		m1, m2   string
		key      string
	}{
		{
			ProtocolS2K,
			"2ecc03e26a4ca980554dd328c9a6877f69623d141466708d067c294b7e3e5815",
			"49cfd96cec137366e34b011251766fbafe51a081655479f7ccf35ca2a4e44628",
			"a10b5d599ea9dbf3a8f2bc7af0ec0e0cb8d405657703077d70a9088ddbf2a05a",
		},
		{
			ProtocolS2KFO,
			"8851b00fb4f2a2d5dbf9fdf4abf7cbe528fd11de3b001681569d07e008a97ab2",
			"3edd05101984381a14f5fffde6b6fbbc0136408953d95366a8f4a1ef761e278f",
			"e17917f5e2258f0cd846ef0d80f35915e085528dd47a55543a23a8c2d3448962",
		},
	} {
		t.Run(string(tc.protocol), func(t *testing.T) {
			client := fixedGrandSlam(t, []byte{1})
			if got := client.PublicKey(); !bytes.Equal(got, []byte{2}) {
				t.Fatalf("A = %x, want 02", got)
			}
			for _, b := range [][]byte{{3}, {0, 0, 3}} {
				proof, err := client.Complete(grandSlamTestUsername, grandSlamTestPassword, decodeGrandSlamHex(t, grandSlamTestSalt), b, grandSlamTestRounds, tc.protocol)
				if err != nil {
					t.Fatal(err)
				}
				checkGrandSlamProof(t, proof, tc.m1, tc.m2, tc.key)
			}
		})
	}
}

func TestGrandSlamServerDerivedVectors(t *testing.T) {
	// Independent Python server: a=07 repeated 32 times, b=09 repeated 32
	// times; v=g^x, B=(k*v+g^b)%N, S=(A*v^u)^b%N. Its K matched the client
	// formula before recording these fixed B, M1, M2, and K values.
	for _, tc := range []struct {
		protocol PasswordProtocol
		b        string
		m1, m2   string
		key      string
	}{
		{
			ProtocolS2K,
			"84646df6aba1530c00efe13cc2bc74c950a06acfa1bcb5ec4ddb2f5cd995c5f1eaeb77efbfc1573e389991c0356c8d897ff3729467b13fe43651cb62791181c3ae7477ad6893ef9d53dad79c061d2d3e6e8af840ea6fad800b1209afbb8a5b194c342372efbe1c097643be8d70086d0369b5368ec774f4761a5d7940f7aea93f80e43dd44c3550cdcd2850d624ad0475dd017acea50fd111d89344ab60a10da505f5e2c81cfc0f2c61defab5f5600b059cd2b190bdaf11730f4157735539fba143a381160821b69678b13eaef9ad2724894ff7859feab5015d29d0c33880ac72d3e4916528fff2a269ffec0c3414dbf2edf637b8f6679b299e5db103d4590cb3",
			"ccf23b9e09b0b4becf9034fb348792f30e44625a13dbeb4171cd759e210c2d1d",
			"ebdbf03854158623172ab21f538200b3fc99eda239450878f51c4e8d3c8eeb65",
			"c84e8798e191c9b107ff38839038b3cb4e20b62e6af2ae6d9a2cf1c5af58674d",
		},
		{
			ProtocolS2KFO,
			"ab43b93df26226c3703117ffae4660b1604a9d08c1db377c998979a78aeb37e1de9c856b50a9b45a2191d8c5a543d4bff0c670c5f7c43cb4e4e1cb549bd024e8f9c254545308831b283b1bea81def76564a23050637c3a355841f26f793602a390465fc59b463a689730027dadb9c8d53eb9d717a32a7454f7360c0d43a89a06a54b52fc44b882ad25313314e7a74fd4b424405cf9864cd1af87bc70506442ab5528bc03f7705ad53ed4fd5bd211e20eb2f936b70d8ca622fd517042b69e61be4e8610339fb600e2343e8c3e953432ed1a56e781dd2db6f5833af108b6c039397d4c7c00258e76b51e5f440b3855cbbb0bf849ee3885ba8271d6865ada8874ca",
			"bb85b54c7def0b751196bed8af941cbd86e76f9ef2f82581125aebd9af5735be",
			"99f08b235b445c1f6f52a8e06ba3a197bc5f6931284a1e0e341be76ce3d98086",
			"814c68e4f5ed11cddc04ebfbcafd412977d4f29b72534c709ea7014066909741",
		},
	} {
		t.Run(string(tc.protocol), func(t *testing.T) {
			client := fixedGrandSlam(t, bytes.Repeat([]byte{7}, 32))
			proof, err := client.Complete(grandSlamTestUsername, grandSlamTestPassword, decodeGrandSlamHex(t, grandSlamTestSalt), decodeGrandSlamHex(t, tc.b), grandSlamTestRounds, tc.protocol)
			if err != nil {
				t.Fatal(err)
			}
			checkGrandSlamProof(t, proof, tc.m1, tc.m2, tc.key)
		})
	}
}

func TestGrandSlamZeroPremasterEncoding(t *testing.T) {
	// Independently choose B=k*g^x mod N, making S=0. num_bigint's zero
	// representation is one zero byte, whereas math/big.Int.Bytes is empty.
	const b = "902b6a8f1779fd9a14ae0210e1d72040306ef6d5ae9cfa2e15a958e6c61b353cbfccc548d6f6fad37b0b018d1547c44ea61de66089be7947bef71185fb6ee9441964a95d50ce5f2b14f6bf3970be2b132edaadc29d3ea3c03d2177471a73de5ad10824959f213792c4f91b5c3194c9b97799386836bfd2eeb50c3bd937aa1e3f9883b3ee65113aa21cf2628674288248b58ce8c3a2ed75eae2eef39bc613038fede2c32d93305dcb03f6e6926137273769104d266984d2967299f40ead5059c6399aeb97daa0b73f02a749dde6a0f33644f2bd5f2b28c8837c9d5b7a4dd48b65da570617aa30c939c46806d0d7d29ce9aaf8e7dff836b9e93ee137d8007b133e"
	proof, err := fixedGrandSlam(t, []byte{1}).Complete(grandSlamTestUsername, grandSlamTestPassword, decodeGrandSlamHex(t, grandSlamTestSalt), decodeGrandSlamHex(t, b), grandSlamTestRounds, ProtocolS2K)
	if err != nil {
		t.Fatal(err)
	}
	checkGrandSlamProof(t, proof,
		"4611872fb0cba3c4b3c16b30a6f4ab3e8916ec49093e591194c1f696852acd10",
		"a59a0d49d5b38922f38f197a7aae8e6f2ee8d610eac234caa0307d26a0e103fc",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	)
}

func TestGrandSlamRejectsInvalidChallenge(t *testing.T) {
	client := fixedGrandSlam(t, []byte{1})
	n := client.s.pf.N
	for _, tc := range []struct {
		name       string
		username   string
		password   string
		salt, b    []byte
		iterations int
		protocol   PasswordProtocol
	}{
		{"zero B", "u", "p", []byte("s"), []byte{0}, 1, ProtocolS2K},
		{"B equals N", "u", "p", []byte("s"), n.Bytes(), 1, ProtocolS2K},
		{"B equals 2N", "u", "p", []byte("s"), new(big.Int).Mul(n, big.NewInt(2)).Bytes(), 1, ProtocolS2K},
		{"long B", "u", "p", []byte("s"), bytes.Repeat([]byte{1}, grandSlamMaxPublicKeySize+1), 1, ProtocolS2K},
		{"long username", strings.Repeat("u", grandSlamMaxCredential+1), "p", []byte("s"), []byte{3}, 1, ProtocolS2K},
		{"long password", "u", strings.Repeat("p", grandSlamMaxCredential+1), []byte("s"), []byte{3}, 1, ProtocolS2K},
		{"long salt", "u", "p", make([]byte, grandSlamMaxSalt+1), []byte{3}, 1, ProtocolS2K},
		{"zero iterations", "u", "p", []byte("s"), []byte{3}, 0, ProtocolS2K},
		{"negative iterations", "u", "p", []byte("s"), []byte{3}, -1, ProtocolS2K},
		{"long iterations", "u", "p", []byte("s"), []byte{3}, grandSlamMaxIterations + 1, ProtocolS2K},
		{"unknown protocol", "u", "p", []byte("s"), []byte{3}, 1, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := client.Complete(tc.username, tc.password, tc.salt, tc.b, tc.iterations, tc.protocol); err == nil {
				t.Fatal("invalid challenge was accepted")
			}
		})
	}

	// The reference rejects multiples of N rather than every B >= N.
	if _, err := client.Complete("u", "p", []byte("s"), new(big.Int).Add(n, big.NewInt(1)).Bytes(), 1, ProtocolS2K); err != nil {
		t.Fatalf("B=N+1 rejected: %v", err)
	}
}

func TestGrandSlamProofVerificationAndCopies(t *testing.T) {
	client, err := NewGrandSlam()
	if err != nil {
		t.Fatal(err)
	}
	public := client.PublicKey()
	if len(public) == 0 || len(public) > 256 {
		t.Fatalf("public key length = %d", len(public))
	}
	wantPublic := bytes.Clone(public)
	public[0] ^= 0xff
	if !bytes.Equal(client.PublicKey(), wantPublic) {
		t.Fatal("PublicKey exposed internal storage")
	}

	proof, err := client.Complete("u", "p", []byte("s"), []byte{3}, 1, ProtocolS2K)
	if err != nil {
		t.Fatal(err)
	}
	good := bytes.Clone(proof.m2)
	if err := proof.VerifyServer(good); err != nil {
		t.Fatal(err)
	}
	for _, accessor := range []struct {
		name string
		get  func() []byte
	}{
		{"Proof", proof.Proof},
		{"SessionKey", proof.SessionKey},
	} {
		want := accessor.get()
		changed := accessor.get()
		changed[0] ^= 0xff
		if !bytes.Equal(accessor.get(), want) {
			t.Errorf("%s exposed internal storage", accessor.name)
		}
	}
	if err := proof.VerifyServer(good); err != nil {
		t.Fatalf("accessor exposed internal proof storage: %v", err)
	}
	bad := bytes.Clone(good)
	bad[0] ^= 0xff
	for _, reply := range [][]byte{nil, good[:len(good)-1], append(bytes.Clone(good), 0), bad} {
		if err := proof.VerifyServer(reply); err == nil {
			t.Fatal("invalid server proof was accepted")
		}
	}
	if err := (&GrandSlamProof{}).VerifyServer(nil); err == nil {
		t.Fatal("empty expected proof was accepted")
	}
}

func fixedGrandSlam(t *testing.T, private []byte) *GrandSlam {
	t.Helper()
	pf, err := findPrimeField(2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &SRP{h: crypto.SHA256, pf: pf, a: new(big.Int).SetBytes(private)}
	s.A = new(big.Int).Exp(pf.g, s.a, pf.N)
	return &GrandSlam{s: s}
}

func decodeGrandSlamHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func checkGrandSlamProof(t *testing.T, proof *GrandSlamProof, m1, m2, key string) {
	t.Helper()
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"M1", proof.Proof(), m1},
		{"M2", proof.m2, m2},
		{"K", proof.SessionKey(), key},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
	}
	if err := proof.VerifyServer(decodeGrandSlamHex(t, m2)); err != nil {
		t.Errorf("VerifyServer: %v", err)
	}
}
