//go:build darwin && cgo

package fairplay

/*
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <string.h>
#include <mach-o/loader.h>

extern int mremap_encrypted(void*, size_t, uint32_t, uint32_t, uint32_t);

static int c_decrypt_data_segment(int fd, size_t offset, size_t len, uint32_t cryptid, void *out) {
    if (fd < 0 || !out || len == 0) return 1;
    void *mapped = mmap(NULL, len, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, (off_t)offset);
    if (mapped == MAP_FAILED) return 2;
    int err = mremap_encrypted(mapped, len, cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
    if (err != 0) {
        munmap(mapped, len);
        return 3;
    }
    memcpy(out, mapped, len);
    if (munmap(mapped, len) != 0) return 4;
    return 0;
}
*/
import "C"
import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	semver "github.com/hashicorp/go-version"
)

// as seen in the reference C code.
func DecryptData(m *macho.File) ([]byte, error) {
	// check for valid macOS version
	buildInfo, err := utils.GetBuildInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get macOS build info: %w", err)
	}
	productVersion, err := semver.NewVersion(buildInfo.ProductVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to parse macOS version: %w", err)
	}
	if productVersion.GreaterThan(semver.Must(semver.NewVersion("11.2.3"))) {
		return nil, fmt.Errorf("macOS version %s is not supported, please use macOS 11.2.3 or below", buildInfo.ProductVersion)
	}

	// check for encryption info
	encryptionInfo := m.GetLoadsByName("LC_ENCRYPTION_INFO_64")
	if len(encryptionInfo) == 0 {
		return nil, fmt.Errorf("LC_ENCRYPTION_INFO_64 not found")
	}

	// get encryption info
	encInfo := encryptionInfo[0].(*macho.EncryptionInfo64)

	// read encrypted data
	encryptedData := make([]byte, encInfo.Size)
	if _, err := m.ReadAt(encryptedData, int64(encInfo.Offset)); err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// write encrypted data to a temp file for file-backed mmap
	tmpFile, err := os.CreateTemp("", "encrypted_section_*.bin")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(encryptedData); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write encrypted data to temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to sync temp file: %w", err)
	}

	// decrypt data
	fd := tmpFile.Fd()
	dataLen := len(encryptedData)
	cryptID := encInfo.CryptID
	decryptedOutput := make([]byte, dataLen)
	cRet := C.c_decrypt_data_segment(
		C.int(fd),
		C.size_t(0), // offset in temp file is always 0
		C.size_t(dataLen),
		C.uint32_t(cryptID),
		unsafe.Pointer(&decryptedOutput[0]),
	)
	tmpFile.Close()
	if cRet != 0 {
		errMsg := fmt.Sprintf("C.c_decrypt_data_segment failed with code %d", cRet)
		switch cRet {
		case 1:
			errMsg += " (invalid arguments)"
		case 2:
			errMsg += " (mmap failed)"
		case 3:
			errMsg += " (mremap_encrypted failed)"
		case 4:
			errMsg += " (munmap failed)"
		}
		return nil, errors.New(errMsg)
	}

	return decryptedOutput, nil
}
