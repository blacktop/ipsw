/*
Copyright © 2025 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package macho

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/fairplay"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoDecryptCmd)
	machoDecryptCmd.Flags().StringP("output", "o", "", "Output path for decrypted binary")
	machoDecryptCmd.Flags().BoolP("force", "f", false, "Overwrite existing file")
	viper.BindPFlag("macho.decrypt.output", machoDecryptCmd.Flags().Lookup("output"))
	viper.BindPFlag("macho.decrypt.force", machoDecryptCmd.Flags().Lookup("force"))
}

// machoDecryptCmd represents the decrypt command
var machoDecryptCmd = &cobra.Command{
	Use:           "decrypt <BUNDLE_ID|PATH>",
	Short:         "Decrypt an App Store app",
	Args:          cobra.ExactArgs(1),
	Hidden:        true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		arg := args[0]
		var binaryPath string

		// Check if argument is a path
		if _, err := os.Stat(arg); err == nil {
			binaryPath = arg
		} else {
			// Assume argument is a Bundle ID and try to find the app
			log.Infof("Searching for app with Bundle ID: %s", arg)
			out, err := exec.Command("mdfind", "kMDItemCFBundleIdentifier == '"+arg+"'").Output()
			if err != nil {
				return fmt.Errorf("failed to search for app: %v", err)
			}
			paths := strings.Split(strings.TrimSpace(string(out)), "\n")
			if len(paths) == 0 || paths[0] == "" {
				return fmt.Errorf("no app found with Bundle ID: %s", arg)
			}

			var selectedApp string
			if len(paths) > 1 {
				prompt := &survey.Select{
					Message: "Found multiple apps, please select one:",
					Options: paths,
				}
				if err := survey.AskOne(prompt, &selectedApp); err != nil {
					return err
				}
			} else {
				selectedApp = paths[0]
			}
			log.Infof("Found app: %s", selectedApp)

			// Find executable in app bundle
			executable, err := getAppExecutable(selectedApp)
			if err != nil {
				return fmt.Errorf("failed to get app executable: %v", err)
			}
			binaryPath = executable
		}

		log.Infof("Decrypting binary: %s", binaryPath)

		return decryptBinary(binaryPath, viper.GetString("macho.decrypt.output"), viper.GetBool("macho.decrypt.force"))
	},
}

func getAppExecutable(appPath string) (string, error) {
	// Read Info.plist to get CFBundleExecutable
	infoPlistPath := filepath.Join(appPath, "Contents", "Info.plist")
	if _, err := os.Stat(infoPlistPath); os.IsNotExist(err) {
		// iOS apps on macOS might be wrapped differently or just be inside the .app
		// Check for Info.plist in root of .app (iOS style)
		infoPlistPath = filepath.Join(appPath, "Info.plist")
	}

	if _, err := os.Stat(infoPlistPath); os.IsNotExist(err) {
		return "", fmt.Errorf("Info.plist not found in %s", appPath)
	}

	appName := filepath.Base(appPath)
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))

	// Check standard locations
	possibleExe := filepath.Join(appPath, "Contents", "MacOS", appName)
	if _, err := os.Stat(possibleExe); err == nil {
		return possibleExe, nil
	}

	possibleExe = filepath.Join(appPath, appName)
	if _, err := os.Stat(possibleExe); err == nil {
		return possibleExe, nil
	}

	return "", fmt.Errorf("could not locate executable for %s", appPath)
}

func decryptBinary(inputPath, outputPath string, force bool) error {
	// 1. Copy input to output (or temp if output not specified)
	if outputPath == "" {
		outputPath = filepath.Base(inputPath) + ".decrypted"
	}

	if _, err := os.Stat(outputPath); err == nil {
		if !force {
			return fmt.Errorf("output file %s already exists", outputPath)
		}
	}

	log.Infof("Creating output file: %s", outputPath)
	if err := copyFile(inputPath, outputPath); err != nil {
		return fmt.Errorf("failed to copy binary: %v", err)
	}

	// 2. Open the copy
	f, err := os.OpenFile(outputPath, os.O_RDWR, 0755)
	if err != nil {
		return fmt.Errorf("failed to open output file: %v", err)
	}
	defer f.Close()

	if fat, err := macho.OpenFat(outputPath); err == nil {
		defer fat.Close()
		log.Infof("Detected universal Mach-O (%d slices)", len(fat.Arches))
		for _, arch := range fat.Arches {
			label := fmt.Sprintf("%s/%s", arch.File.CPU.String(), arch.File.SubCPU.String(arch.File.CPU))
			if err := decryptSlice(f, arch.File, int64(arch.Offset), label); err != nil {
				return err
			}
		}
		log.Info("Decryption complete!")
		return nil
	} else if !errors.Is(err, macho.ErrNotFat) {
		return fmt.Errorf("failed to parse MachO: %v", err)
	}

	// 3. Use blacktop/go-macho to parse thin Mach-O
	m, err := macho.Open(outputPath)
	if err != nil {
		return fmt.Errorf("failed to parse MachO: %v", err)
	}
	defer m.Close()

	if err := decryptSlice(f, m, 0, m.CPU.String()); err != nil {
		return err
	}

	log.Info("Decryption complete!")
	return nil
}

type encryptionInfo struct {
	offset  uint32
	size    uint32
	cryptID uint32
}

func getEncryptionInfo(m *macho.File) (*encryptionInfo, error) {
	if infos := m.GetLoadsByName("LC_ENCRYPTION_INFO_64"); len(infos) > 0 {
		encInfo := infos[0].(*macho.EncryptionInfo64)
		return &encryptionInfo{offset: encInfo.Offset, size: encInfo.Size, cryptID: uint32(encInfo.CryptID)}, nil
	}
	if infos := m.GetLoadsByName("LC_ENCRYPTION_INFO"); len(infos) > 0 {
		encInfo := infos[0].(*macho.EncryptionInfo)
		return &encryptionInfo{offset: encInfo.Offset, size: encInfo.Size, cryptID: uint32(encInfo.CryptID)}, nil
	}
	return nil, fmt.Errorf("no encryption info found")
}

func decryptSlice(f *os.File, m *macho.File, baseOffset int64, label string) error {
	encInfo, err := getEncryptionInfo(m)
	if err != nil {
		return fmt.Errorf("%s: %v", label, err)
	}
	if encInfo.cryptID == 0 {
		log.Warnf("%s: cryptid is already 0; skipping decryption", label)
		return nil
	}

	data, err := fairplay.DecryptData(m)
	if err != nil {
		return fmt.Errorf("%s: decryption failed: %v", label, err)
	}

	writeOffset := baseOffset + int64(encInfo.offset)
	log.Infof("%s: writing decrypted data at offset 0x%x (size: %d)", label, writeOffset, len(data))
	if _, err := f.WriteAt(data, writeOffset); err != nil {
		return fmt.Errorf("%s: failed to write decrypted data: %v", label, err)
	}

	if err := patchCryptID(f, m, baseOffset, label); err != nil {
		return err
	}
	return nil
}

func patchCryptID(f *os.File, m *macho.File, baseOffset int64, label string) error {
	cmdOffset := int64(m.HdrSize())
	ncmds := m.NCommands
	cmdsz := m.SizeCommands

	loadCommands := make([]byte, cmdsz)
	if _, err := f.ReadAt(loadCommands, baseOffset+cmdOffset); err != nil {
		return fmt.Errorf("%s: failed to read load commands: %v", label, err)
	}

	r := bytes.NewReader(loadCommands)
	var cmd, cmdSize uint32

	// LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2C
	const (
		LC_ENCRYPTION_INFO    = 0x21
		LC_ENCRYPTION_INFO_64 = 0x2C
	)

	for i := 0; i < int(ncmds); i++ {
		startPos, _ := r.Seek(0, io.SeekCurrent)
		if err := binary.Read(r, m.ByteOrder, &cmd); err != nil {
			return fmt.Errorf("%s: failed to read load command: %v", label, err)
		}
		if err := binary.Read(r, m.ByteOrder, &cmdSize); err != nil {
			return fmt.Errorf("%s: failed to read load command size: %v", label, err)
		}

		if cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64 {
			cryptidOffset := baseOffset + cmdOffset + startPos + 16
			log.Infof("%s: patching cryptid at offset 0x%x", label, cryptidOffset)
			zero := []byte{0, 0, 0, 0}
			if _, err := f.WriteAt(zero, cryptidOffset); err != nil {
				return fmt.Errorf("%s: failed to zero cryptid: %v", label, err)
			}
			return nil
		}

		if cmdSize < 8 {
			return fmt.Errorf("%s: invalid load command size %d", label, cmdSize)
		}
		if _, err := r.Seek(startPos+int64(cmdSize), io.SeekStart); err != nil {
			return fmt.Errorf("%s: failed to seek to next command: %v", label, err)
		}
	}

	return fmt.Errorf("%s: encryption info load command not found", label)
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
