package macho

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc/v2"
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

func init() { MachoCmd.AddCommand(newMachoDecryptIPACmd(fairplay.DecryptIPA)) }

func newMachoDecryptIPACmd(decrypt func(string, string, string) (fairplay.Result, error)) *cobra.Command {
	command := &cobra.Command{
		Use:   "decrypt-ipa <IPA>",
		Short: "Decrypt an IPA using an exported local authorization file",
		Long: "Decrypt a licensed IPA into a new output directory. The authorization exported by " +
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
			result, err := decrypt(args[0], authorization, output)
			if err != nil {
				return err
			}
			cmd.Println("Decrypted IPA written to", output)
			if result.ParentSyncUnconfirmed {
				cmd.PrintErrln("Output was published, but directory durability could not be confirmed.")
			}
			return nil
		},
	}
	command.Flags().String("auth", "",
		"Exported local authorization file (default ~/.config/ipsw/fairplay/authorization.fpauth)")
	command.Flags().StringP("output", "o", "", "New output directory (must not exist)")
	_ = command.MarkFlagRequired("output")
	_ = command.MarkFlagFilename("auth")
	return command
}
