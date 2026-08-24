package download

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
)

const (
	chunklistMagic       = 0x4C4B4E43 // 'CNKL'
	chunklistVersion     = 1
	chunklistChunkMethod = 1
	chunklistRSASigSize  = 256

	// This is the conventional big-endian representation of Apple's rev1
	// production RSA modulus. The Apple CDN fixture test pins the key.
	chunklistProductionModulus = "C3E748CAD9CD384329E10E25A91E43E1A762FF529ADE578C935BDDF9B13F2179" +
		"D4855E6FC89E9E29CA12517D17DFA1EDCE0BEBF0EA7B461FFE61D94E2BDF72C1" +
		"96F89ACD3536B644064014DAE25A15DB6BB0852ECBD120916318D1CCDEA3C84C9" +
		"2ED743FC176D0BACA920D3FCF3158AFF731F88CE0623182A8ED67E650515F7574" +
		"5909F07D415F55FC15A35654D118C55A462D37A3ACDA08612F3F3F6571761EFC" +
		"CBCC299AEE99B3A4FD6212CCFFF5EF37A2C334E871191F7E1C31960E010A54E86" +
		"FA3F62E6D6905E1CD57732410A3EB0C6B4DEFDABE9F59BF1618758C751CD56CEF" +
		"851D1C0EAA1C558E37AC108DA9089863D20E2E7E4BF475EC66FE6B3EFDCF"
)

var errPackageIntegrityMismatch = errors.New("package integrity check failed")

type chunkSignatureMethod uint8

const (
	chunkSignatureMethodNone chunkSignatureMethod = iota
	chunkSignatureMethodRev1RSA
	chunkSignatureMethodSHA256
)

type chunklistHeader struct {
	Magic           uint32
	HeaderSize      uint32
	Version         uint8
	ChunkMethod     uint8
	SignatureMethod chunkSignatureMethod
	Padding         uint8
	ChunkCount      uint64
	ChunkOffset     uint64
	SignatureOffset uint64
}

type chunklistChunk struct {
	Size uint32
	Hash [sha256.Size]byte
}

func parseChunklist(data []byte) ([]chunklistChunk, error) {
	headerSize := binary.Size(chunklistHeader{})
	chunkSize := binary.Size(chunklistChunk{})
	if len(data) < headerSize {
		return nil, fmt.Errorf("integrity chunklist is shorter than its header")
	}

	var header chunklistHeader
	if err := binary.Read(bytes.NewReader(data[:headerSize]), binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read integrity chunklist: %w", err)
	}
	if header.Magic != chunklistMagic || header.HeaderSize != uint32(headerSize) ||
		header.Version != chunklistVersion || header.ChunkMethod != chunklistChunkMethod || header.Padding != 0 {
		return nil, fmt.Errorf("unsupported integrity chunklist format")
	}
	if header.ChunkCount == 0 {
		return nil, fmt.Errorf("integrity chunklist contains no chunks")
	}

	dataSize := uint64(len(data))
	if header.ChunkOffset < uint64(headerSize) || header.ChunkOffset > dataSize {
		return nil, fmt.Errorf("invalid integrity chunk offset %d", header.ChunkOffset)
	}
	if header.ChunkCount > (dataSize-header.ChunkOffset)/uint64(chunkSize) {
		return nil, fmt.Errorf("integrity chunk table exceeds the chunklist")
	}
	chunksEnd := header.ChunkOffset + header.ChunkCount*uint64(chunkSize)

	signatureSize, err := chunklistSignatureSize(header.SignatureMethod)
	if err != nil {
		return nil, err
	}
	if header.SignatureOffset < chunksEnd || header.SignatureOffset > dataSize ||
		dataSize-header.SignatureOffset != uint64(signatureSize) {
		return nil, fmt.Errorf("invalid integrity signature offset or size")
	}
	if err := verifyChunklistSignature(data, header); err != nil {
		return nil, err
	}

	chunks := make([]chunklistChunk, int(header.ChunkCount))
	chunkData := data[int(header.ChunkOffset):int(chunksEnd)]
	if err := binary.Read(bytes.NewReader(chunkData), binary.LittleEndian, chunks); err != nil {
		return nil, fmt.Errorf("failed to read integrity chunks: %w", err)
	}
	for idx, chunk := range chunks {
		if chunk.Size == 0 {
			return nil, fmt.Errorf("integrity chunk #%d has zero size", idx)
		}
	}
	return chunks, nil
}

func chunklistSignatureSize(method chunkSignatureMethod) (int, error) {
	switch method {
	case chunkSignatureMethodRev1RSA:
		return chunklistRSASigSize, nil
	case chunkSignatureMethodSHA256:
		return sha256.Size, nil
	default:
		return 0, fmt.Errorf("unsupported integrity signature method %d", method)
	}
}

func verifyChunklistSignature(data []byte, header chunklistHeader) error {
	signatureOffset := int(header.SignatureOffset)
	digest := sha256.Sum256(data[:signatureOffset])
	signature := data[signatureOffset:]

	switch header.SignatureMethod {
	case chunkSignatureMethodRev1RSA:
		modulus, ok := new(big.Int).SetString(chunklistProductionModulus, 16)
		if !ok {
			return fmt.Errorf("invalid embedded chunklist public key")
		}
		// Rev1 stores the RSA signature least-significant byte first.
		signature = append([]byte(nil), signature...)
		for left, right := 0, len(signature)-1; left < right; left, right = left+1, right-1 {
			signature[left], signature[right] = signature[right], signature[left]
		}
		key := &rsa.PublicKey{N: modulus, E: 65537}
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("invalid integrity chunklist RSA signature: %w", err)
		}
	case chunkSignatureMethodSHA256:
		if !bytes.Equal(signature, digest[:]) {
			return fmt.Errorf("invalid integrity chunklist SHA-256 digest")
		}
	default:
		return fmt.Errorf("unsupported integrity signature method %d", header.SignatureMethod)
	}
	return nil
}

func verifyPackageChunks(packagePath string, chunks []chunklistChunk) error {
	f, err := os.Open(packagePath)
	if err != nil {
		return fmt.Errorf("failed to open package: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat package: %w", err)
	}
	var covered uint64
	for _, chunk := range chunks {
		covered += uint64(chunk.Size)
	}
	if info.Size() < 0 || covered != uint64(info.Size()) {
		return fmt.Errorf("%w: chunks cover %d bytes, package contains %d", errPackageIntegrityMismatch, covered, info.Size())
	}

	for idx, chunk := range chunks {
		digest := sha256.New()
		if _, err := io.CopyN(digest, f, int64(chunk.Size)); err != nil {
			return fmt.Errorf("failed to read package chunk #%d: %w", idx, err)
		}
		if !bytes.Equal(digest.Sum(nil), chunk.Hash[:]) {
			return fmt.Errorf("%w: chunk #%d digest mismatch", errPackageIntegrityMismatch, idx)
		}
	}
	finalInfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to restat package: %w", err)
	}
	if finalInfo.Size() < 0 || covered != uint64(finalInfo.Size()) {
		return fmt.Errorf("%w: package size changed during verification", errPackageIntegrityMismatch)
	}
	return nil
}
