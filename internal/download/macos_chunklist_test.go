package download

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseChunklistAcceptsAppleRev1Signature(t *testing.T) {
	// Product 061-26578-A's AppleDiagnostics.chunklist from Apple's public
	// software-update CDN, SHA-256
	// 4f92f5e222c6fdac1ac18480105cb3c261459057cb192b2929e59db6ff7211b9.
	const encoded = "Q05LTCQAAAABAQEAAQAAAAAAAAAkAAAAAAAAAEgAAAAAAAAA824tAIW6SIF6Gw4Wdm/IB5JCSrPiXiXGyLPb9ow4K2cs0iXLrExJacA/ceVdU/r9HlTVyYLvh3MBJRVBQz/Fc8/8/P77z/HMeDd8imIsgSwvNAzb9L6xrbOi1NsdcQ+SjdYbyG7ildi9juK7mGckYfobVpBsHb6kWl8vXF6w4j5EHf5SDZXn1af9bCGTbMhHXICc7d6ZmTPbbLwczyN3VtjHCpDf/KAmOPu/ENtdZbyzg5LXVHgurx5gsn0dCYiO3EryzANm9mthx3CSKtJ38ABY+QE9i/601wVgPCSf2AXnapPj2F3UMicknUBjSsYS6JcaFHGVMk7isQacCZ0WLVGbkqez2nSJ8jrWbPztYE52sQ96zx6G3qVUZKTM8v/UFbH0kg=="
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), data...)

	chunks, err := parseChunklist(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 || chunks[0].Size != 2_977_523 {
		t.Fatalf("chunks = %#v, want one 2,977,523-byte chunk", chunks)
	}
	if !bytes.Equal(data, original) {
		t.Fatal("parseChunklist mutated its input")
	}

	data[len(data)-1] ^= 1
	if _, err := parseChunklist(data); err == nil || !strings.Contains(err.Error(), "RSA signature") {
		t.Fatalf("mutated signature error = %v, want RSA signature failure", err)
	}
}

func TestVerifyPackageIntegrity(t *testing.T) {
	parts := [][]byte{[]byte("first chunk"), []byte("second chunk")}
	integrityData := makeSHA256Chunklist(t, parts...)
	packagePath := filepath.Join(t.TempDir(), "package.pkg")
	good := bytes.Join(parts, nil)
	if err := os.WriteFile(packagePath, good, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyTestPackageIntegrity(packagePath, integrityData); err != nil {
		t.Fatal(err)
	}

	corrupt := append([]byte(nil), good...)
	corrupt[0] ^= 1
	if err := os.WriteFile(packagePath, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyTestPackageIntegrity(packagePath, integrityData); err == nil || !strings.Contains(err.Error(), "chunk #0") {
		t.Fatalf("corrupt package error = %v, want first-chunk failure", err)
	}

	if err := os.WriteFile(packagePath, append(good, 0), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyTestPackageIntegrity(packagePath, integrityData); err == nil || !strings.Contains(err.Error(), "package contains") {
		t.Fatalf("trailing-data error = %v, want full-file coverage failure", err)
	}
}

func TestVerifyPackageIntegrityAcceptsAppleSHA256Fixture(t *testing.T) {
	// Product 142-00150-A's InstallInfo.plist and integrityDataV1 from Apple's
	// public software-update CDN. Their SHA-256 digests are respectively
	// 97704a8960b4facceef54397a08fb5d0a456247c3627359215aa2a27df22656c and
	// 944830c4ab32b30fb54abe63ab87216611b3c7bf6c80c226740dc901b3701654.
	const encodedPackage = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdC8+CjwvcGxpc3Q+Cg=="
	const encodedIntegrity = "Q05LTCQAAAABAQIAAQAAAAAAAAAkAAAAAAAAAEgAAAAAAAAAtQAAAJdwSolgtPrM7vVDl6CPtdCkViR8Nic1khWqKiffImVsnISVgMsF8r+R0BDeh+0Ii43is/jIr8z9jkCrGIFwwkQ="
	packageData, err := base64.StdEncoding.DecodeString(encodedPackage)
	if err != nil {
		t.Fatal(err)
	}
	integrityData, err := base64.StdEncoding.DecodeString(encodedIntegrity)
	if err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(t.TempDir(), "InstallInfo.plist")
	if err := os.WriteFile(packagePath, packageData, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyTestPackageIntegrity(packagePath, integrityData); err != nil {
		t.Fatal(err)
	}
}

func verifyTestPackageIntegrity(packagePath string, integrityData []byte) error {
	chunks, err := parseChunklist(integrityData)
	if err != nil {
		return err
	}
	return verifyPackageChunks(packagePath, chunks)
}

func TestParseChunklistRejectsUnsupportedAndMalformedData(t *testing.T) {
	valid := makeSHA256Chunklist(t, []byte("payload"))
	tests := map[string]func([]byte){
		"no signature":      func(data []byte) { data[10] = byte(chunkSignatureMethodNone) },
		"unknown signature": func(data []byte) { data[10] = 99 },
		"bad magic":         func(data []byte) { data[0] = 0 },
		"zero chunks": func(data []byte) {
			for idx := 12; idx < 20; idx++ {
				data[idx] = 0
			}
		},
		"bad digest": func(data []byte) { data[len(data)-1] ^= 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(nil), valid...)
			mutate(data)
			if _, err := parseChunklist(data); err == nil {
				t.Fatal("parseChunklist accepted invalid data")
			}
		})
	}
	if _, err := parseChunklist(valid[:len(valid)-1]); err == nil {
		t.Fatal("parseChunklist accepted a truncated signature")
	}
}

func makeSHA256Chunklist(t *testing.T, parts ...[]byte) []byte {
	t.Helper()
	headerSize := binary.Size(chunklistHeader{})
	chunkSize := binary.Size(chunklistChunk{})
	header := chunklistHeader{
		Magic:           chunklistMagic,
		HeaderSize:      uint32(headerSize),
		Version:         chunklistVersion,
		ChunkMethod:     chunklistChunkMethod,
		SignatureMethod: chunkSignatureMethodSHA256,
		ChunkCount:      uint64(len(parts)),
		ChunkOffset:     uint64(headerSize),
		SignatureOffset: uint64(headerSize + chunkSize*len(parts)),
	}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	for _, part := range parts {
		if len(part) == 0 {
			t.Fatal("test chunk must not be empty")
		}
		chunk := chunklistChunk{Size: uint32(len(part)), Hash: sha256.Sum256(part)}
		if err := binary.Write(&data, binary.LittleEndian, chunk); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(data.Bytes())
	data.Write(digest[:])
	return data.Bytes()
}
