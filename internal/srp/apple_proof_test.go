package srp

import (
	"crypto"
	"encoding/hex"
	"math/big"
	"testing"
)

// Reference proofs computed with fastlane-sirp 1.1.0 (Apple's SRP variant) from
// the same fixed inputs.
func TestAppleProofMatchesFastlane(t *testing.T) {
	aBytes, _ := hex.DecodeString("ce1195df020de59e0d65a33a4279f1183e7ae4e5d980e309f8b55adff2e61c3ef55ff16f66f43360266b95db6f8fec01d76031054306ae4a4b380598f6cfd1142c3a4249d77070058649dbd822dcaf7957586fce428cfb2ca88b94741eda8b07f46dd28a5499d8efef0b8fb8ee1ec1c5a5e407c9381741d576ba8deb4f59ec3f4539e4b4889079c2a00afeae0bfc1439840ef2379a1fb81c8ba27361ad476d6b66220e71591b2d933c0e935c138ebfd60710b91fe2fb7599eced4430b3dbb3c9730bea4ff16f200fb931b06cae08a5da8e279813775d7ed81e680b4a77946fe120377cec9f51f6bf5ba1fa64649f3b1614e4eee833fd0fc5893f24f6e0accbaf")
	bBytes, _ := hex.DecodeString("7f816a1560db947d6ff798e30909816f400f14230e9a06afac8f8b213127aa215b950e77941d01cdf246d00b1ece546bc95234b77d98b44c9187e2733afa696aabdbc2b5cc2c7a519b72bf7a164c58ebf892ab0c2df6468213705cc2f0da85610cd20d37dbaa799d1d2f6f04adbab0b9e958b083f38e06512cdefadd20863f98239fd09dd1c48679b74cec2120cd5e448b002c728c05e9b10f2c19f298fbdd575ba2c833c5d65e649e4b4fa4d426223f3300650f874e32c4451d9346ce6469e29d574e1d3c5ed212edee33e2478e5a62cdecc5b5cb365479c4eb99e9d342aa38f86ae46d947e2215ce53b1ae840af949b5f686e69ea2f6b7eaf3725619d4303e")
	salt, _ := hex.DecodeString("2bc990059473448e6ebd442aa16bfaa0567ac03dd094876bdb1fd834abe42c1e")
	username := []byte("synthetic@example.com")
	password := []byte("synthetic-pass-Δ1")
	const iteration = 20309

	cases := []struct {
		protocol PasswordProtocol
		m1, m2   string
	}{
		{ProtocolS2K, "f8ffdfb9111079d5c130e22fb0d675f90e53182301d46fe116e29df35daa584f", "446969b3ce382010eaadbaada5caa7ee5f50c52443d4ff10d2c04841aa7af57a"},
		{ProtocolS2KFO, "fe00a59cb9949584f74d2aecddfa679162bcfea056a3844def51d6076ee3dd0f", "84436cc428d5076cf048fec1ad162834a4e93b669a965bbf8f322df6deb5b959"},
	}
	for _, tc := range cases {
		t.Run(string(tc.protocol), func(t *testing.T) {
			s, err := NewWithHash(crypto.SHA256, 2048)
			if err != nil {
				t.Fatal(err)
			}
			s.a = new(big.Int).SetBytes(aBytes)
			s.A = new(big.Int).Exp(s.pf.g, s.a, s.pf.N)
			cli, err := s.NewClient(username, password, salt, iteration, tc.protocol)
			if err != nil {
				t.Fatal(err)
			}
			m1, m2, err := cli.Generate(salt, bBytes)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(m1); got != tc.m1 {
				t.Errorf("M1 = %s, want %s", got, tc.m1)
			}
			if got := hex.EncodeToString(m2); got != tc.m2 {
				t.Errorf("M2 = %s, want %s", got, tc.m2)
			}
		})
	}
}
