package macho

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/fairplay"
	"github.com/spf13/cobra"
)

const authorizationFilename = "authorization.fpauth"

// defaultAuthorizationDirectory is the private directory beside ipsw's config
// where export-auth saves, and decrypt-ipa looks for, authorization.fpauth.
func defaultAuthorizationDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not locate the home directory; pass an explicit path: %w", err)
	}
	return filepath.Join(home, ".config", "ipsw", "fairplay"), nil
}

type decryptIPAFunc func(ipa, authorization, output string) (fairplay.Result, error)

// decryptInto makes a rerun replace the earlier result. The engine only writes a new
// directory, so an existing output receives a fresh result decrypted inside it.
func decryptInto(
	decrypt decryptIPAFunc, ipa, authorization, output string,
) (fairplay.Result, error) {
	info, err := os.Stat(output)
	if errors.Is(err, fs.ErrNotExist) {
		return decrypt(ipa, authorization, output)
	}
	if err != nil {
		return fairplay.Result{}, err
	}
	if !info.IsDir() {
		return fairplay.Result{}, fmt.Errorf("output %q exists and is not a directory", output)
	}
	staging, err := os.MkdirTemp(output, ".decrypt-ipa-")
	if err != nil {
		return fairplay.Result{}, err
	}
	defer os.RemoveAll(staging)
	fresh := filepath.Join(staging, "result")
	result, err := decrypt(ipa, authorization, fresh)
	if err != nil {
		return fairplay.Result{}, err
	}
	entries, err := os.ReadDir(fresh)
	if err != nil {
		return fairplay.Result{}, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if err := os.Rename(filepath.Join(fresh, name), filepath.Join(output, name)); err != nil {
			return fairplay.Result{}, err
		}
	}
	if err := syncDirectory(output); err != nil {
		result.ParentSyncUnconfirmed = true
	}
	return result, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func init() { MachoCmd.AddCommand(newMachoDecryptIPACmd(fairplay.DecryptIPA)) }

func newMachoDecryptIPACmd(decrypt decryptIPAFunc) *cobra.Command {
	command := &cobra.Command{
		Use:   "decrypt-ipa <IPA>",
		Short: "Decrypt an IPA using an exported local authorization file",
		Long: "Decrypt a licensed IPA to repacked.ipa in the output directory, replacing an earlier " +
			"result there. The authorization exported by " +
			"'ipsw macho export-auth' is read from ~/.config/ipsw/fairplay/authorization.fpauth " +
			"unless --auth names another file.",
		Example: heredoc.Doc(`
			# Decrypt a licensed IPA using ~/.config/ipsw/fairplay/authorization.fpauth
			❯ ipsw macho decrypt-ipa ./LicensedApp.ipa --output ./decrypted-app

			# Decrypt using an authorization file from another location
			❯ ipsw macho decrypt-ipa ./LicensedApp.ipa --auth ./authorization.fpauth --output ./decrypted-app`),
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			authorization, err := cmd.Flags().GetString("auth")
			if err != nil {
				return err
			}
			output, err := cmd.Flags().GetString("output")
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("auth") {
				directory, err := defaultAuthorizationDirectory()
				if err != nil {
					return err
				}
				authorization = filepath.Join(directory, authorizationFilename)
			}
			if authorization == "" || output == "" {
				return fmt.Errorf("--auth and --output must be nonempty")
			}
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			result, err := decryptInto(decrypt, args[0], authorization, output)
			if err != nil {
				return err
			}
			log.Infof("Decrypted IPA written to %s", output)
			if result.ParentSyncUnconfirmed {
				log.Warn("Output was published, but directory durability could not be confirmed")
			}
			return nil
		},
	}
	command.Flags().String("auth", "",
		"Exported local authorization file (default ~/.config/ipsw/fairplay/authorization.fpauth)")
	command.Flags().StringP("output", "o", ".", "Output directory (created if missing)")
	_ = command.MarkFlagFilename("auth")
	return command
}
