package aea

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/lzfse-cgo"
	"github.com/dustin/go-humanize"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sync/errgroup"
)

const (
	mainKeyInfo            = "AEA_AMK"
	clusterKeyInfo         = "AEA_CK"
	clusterKeyMaterialInfo = "AEA_CHEK"
	segmentKeyInfo         = "AEA_SK"
)

type clusterHeaderKey struct {
	MAC [32]byte
	Key [32]byte
	IV  [aes.BlockSize]byte
}

type segmentHeader struct {
	DecompressedSize uint32
	RawSize          uint32
	Checksum         [32]byte
}

type ClusterHeader struct {
	NumSegments      uint32
	DecompressedSize uint32
	RawSize          uint32
	Segments         []segmentHeader
}

type work struct {
	ClusterIndex uint32
	Data         []byte
}

func decryptCTR(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES cipher: %v", err)
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func decryptCluster(ctx context.Context, r io.ReadSeeker, key []byte, out chan work) error {
	defer close(out)
	eg, _ := errgroup.WithContext(ctx)

	data := make([]byte, 0x2800)
	clusterKey := make([]byte, 32)

	cindex := uint32(0)

	for {
		info := new(bytes.Buffer)
		if err := binary.Write(info, binary.LittleEndian, []byte(clusterKeyInfo)); err != nil {
			return err
		}
		if err := binary.Write(info, binary.LittleEndian, uint32(cindex)); err != nil {
			return err
		}
		if n, err := hkdf.New(sha256.New, key, []byte{}, info.Bytes()).Read(clusterKey); n != 32 || err != nil {
			return err
		}
		// read clusterHeader
		var chkey clusterHeaderKey
		if err := binary.Read(hkdf.New(sha256.New, clusterKey, []byte{}, []byte(clusterKeyMaterialInfo)), binary.LittleEndian, &chkey); err != nil {
			return err
		}

		n, err := r.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		} else if n < 0x2800 {
			return fmt.Errorf("invalid cluster header size: %#x; expected 0x2800", n)
		}

		r.Seek(0x20, io.SeekCurrent)   // maybe cluster header auth tag?
		r.Seek(0x2000, io.SeekCurrent) // per-segment auth tags

		clusterHdrData, err := decryptCTR(data, chkey.Key[:], chkey.IV[:])
		if err != nil {
			return err
		}
		var hdr ClusterHeader
		hdr.Segments = make([]segmentHeader, 256)
		if err := binary.Read(bytes.NewReader(clusterHdrData), binary.LittleEndian, hdr.Segments); err != nil {
			return err
		}
		if hdr.Segments[0].DecompressedSize > 0x100000 {
			break // TODO: RE last cluster
		}
		// decrypt segments
		segments := make([][]byte, 256)
		for idx, seg := range hdr.Segments {
			if seg.DecompressedSize == 0 {
				continue
			}
			segmentData := make([]byte, seg.RawSize)
			if _, err = r.Read(segmentData); err != nil {
				return err
			}
			func(index int, data []byte, size uint32) {
				eg.Go(func() error {
					info := new(bytes.Buffer)
					if err := binary.Write(info, binary.LittleEndian, []byte(segmentKeyInfo)); err != nil {
						return err
					}
					if err := binary.Write(info, binary.LittleEndian, uint32(index)); err != nil {
						return err
					}
					var segmentKey clusterHeaderKey
					if err := binary.Read(hkdf.New(sha256.New, clusterKey, []byte{}, info.Bytes()), binary.LittleEndian, &segmentKey); err != nil {
						return err
					}
					decryptedData, err := decryptCTR(data, segmentKey.Key[:], segmentKey.IV[:])
					if err != nil {
						return err
					}
					if bytes.Contains(decryptedData[:4], []byte("bvx2")) {
						decomp := lzfse.DecodeBuffer(decryptedData)
						log.WithFields(log.Fields{
							"cluster": cindex,
							"segment": index,
							"size":    humanize.IBytes(uint64(len(decomp))),
							"all":     len(decomp) == int(size),
						}).Debug("LZFSE")
						segments[index] = decomp
						// <-decomp
					} else {
						log.WithFields(log.Fields{
							"cluster": cindex,
							"segment": index,
							"size":    humanize.IBytes(uint64(len(decryptedData))),
							"all":     len(decryptedData) == int(size),
						}).Debug("NOCOMPRESS")
						segments[index] = decryptedData
						// <-decryptedData
					}
					return nil
				})
			}(idx, segmentData, seg.DecompressedSize)
		}

		if err := eg.Wait(); err != nil {
			return err
		}

		out <- work{ClusterIndex: cindex, Data: bytes.Join(segments, nil)}

		cindex++
	}

	return nil
}

func aeaDecrypt(in, out string, akey []byte) (string, error) {
	f, err := os.Open(in)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var hdr Header
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		return "", err
	}

	if string(hdr.Magic[:]) != "AEA1" {
		return "", fmt.Errorf("invalid AEA header: found '%s' expected 'AEA1'", string(hdr.Magic[:]))
	}

	f.Seek(int64(hdr.Length), io.SeekCurrent)

	salt := make([]byte, 32)
	if _, err := f.Read(salt); err != nil {
		return "", err
	}

	info := new(bytes.Buffer)
	if err := binary.Write(info, binary.LittleEndian, []byte(mainKeyInfo)); err != nil {
		return "", err
	}
	if err := binary.Write(info, binary.LittleEndian, uint32(1)); err != nil {
		return "", err
	}

	key := make([]byte, len(akey))
	if n, err := hkdf.New(sha256.New, akey, salt, info.Bytes()).Read(key); n != len(key) || err != nil {
		return "", err
	}

	f.Seek(0x70, io.SeekCurrent) // TODO: WAT is this?

	dec := make(chan work)
	go func() {
		if err := decryptCluster(context.Background(), f, key, dec); err != nil {
			log.WithError(err).Error("failed to decrypt cluster")
		}
	}()

	of, err := os.Create(out)
	if err != nil {
		return "", err
	}
	defer of.Close()

	total := 0
	for d := range dec {
		log.Debugf("Writing cluster %d", d.ClusterIndex)
		if n, err := of.Write(d.Data); err != nil {
			return "", err
		} else {
			log.Debugf("Wrote %s", humanize.IBytes(uint64(n)))
			total += n
		}
	}
	log.Debugf("TOTAL: %s", humanize.IBytes(uint64(total)))

	return out, nil
}

func Decrypt(in, out string, privKeyData []byte) (string, error) {
	metadata, err := Info(in)
	if err != nil {
		return "", fmt.Errorf("failed to parse AEA: %v", err)
	}

	wkey, err := metadata.DecryptFCS(privKeyData)
	if err != nil {
		return "", fmt.Errorf("failed to HPKE decrypt fcs-key: %v", err)
	}

	// if true {
	if _, err := os.Stat(aeaBinPath); os.IsNotExist(err) { // 'aea' binary NOT found (linux/windows)
		log.Info("Using pure Go implementation for AEA decryption")
		return aeaDecrypt(in, filepath.Join(out, filepath.Base(strings.TrimSuffix(in, filepath.Ext(in)))), wkey)
	}
	// use 'aea' binary (as is the fastest way to decrypt AEA on macOS)
	return aea(in, filepath.Join(out, filepath.Base(strings.TrimSuffix(in, filepath.Ext(in)))), base64.StdEncoding.EncodeToString(wkey))
}

func aea(in, out, key string) (string, error) {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command(aeaBinPath, "decrypt", "-i", in, "-o", out, "-key-value", fmt.Sprintf("base64:%s", key))
		cout, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, cout)
		}
		return out, nil
	}
	return "", fmt.Errorf("only supported on macOS (due to `aea` binary requirement)")
}
