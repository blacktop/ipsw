/*
Copyright © 2018-2026 blacktop

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
package ota

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var validCryptexes = []string{"app", "system"}

// otaExtractFlags is the resolved flag state for one `ota extract` invocation.
type otaExtractFlags struct {
	args         []string
	cryptex      string
	pattern      string
	payloadRange string
	output       string
	dyldArches   []string
	dyld         bool
	kernel       bool
	confirm      bool
	json         bool
	decomp       bool
	flat         bool
}

func otaExtractFlagsFromViper(args []string) otaExtractFlags {
	return otaExtractFlags{
		args:         args,
		cryptex:      viper.GetString("ota.extract.cryptex"),
		pattern:      viper.GetString("ota.extract.pattern"),
		payloadRange: viper.GetString("ota.extract.range"),
		output:       viper.GetString("ota.extract.output"),
		dyldArches:   viper.GetStringSlice("ota.extract.dyld-arch"),
		dyld:         viper.GetBool("ota.extract.dyld"),
		kernel:       viper.GetBool("ota.extract.kernel"),
		confirm:      viper.GetBool("ota.extract.confirm"),
		json:         viper.GetBool("ota.extract.json"),
		decomp:       viper.GetBool("ota.extract.decomp"),
		flat:         viper.GetBool("ota.extract.flat"),
	}
}

func (f otaExtractFlags) targeted() bool {
	return f.cryptex != "" || f.dyld || f.kernel || f.pattern != ""
}

func validateOTAExtractArgs(f otaExtractFlags) error {
	if err := cobra.RangeArgs(1, 2)(nil, f.args); err != nil {
		return err
	}
	if err := validateOTAFilenameArgs(f); err != nil {
		return err
	}
	if err := validateOTADyldArgs(f); err != nil {
		return err
	}
	return validateOTAJSONArgs(f)
}

func validateOTAFilenameArgs(f otaExtractFlags) error {
	if len(f.args) != 2 {
		return nil
	}
	if f.pattern != "" {
		return fmt.Errorf("cannot use both FILENAME and --pattern")
	}
	if f.cryptex != "" || f.dyld || f.kernel {
		return fmt.Errorf("cannot use FILENAME with --cryptex, --dyld, or --kernel")
	}
	return nil
}

func validateOTADyldArgs(f otaExtractFlags) error {
	if len(f.dyldArches) > 0 && !f.dyld {
		return fmt.Errorf("--dyld-arch or -a can only be used with --dyld or -d")
	}
	for _, arch := range f.dyldArches {
		if !utils.StrSliceHas(dyld.DscArches, arch) {
			return fmt.Errorf("invalid --dyld-arch: '%s' (must be one of %s)",
				arch, strings.Join(dyld.DscArches, ", "))
		}
	}
	if f.payloadRange != "" && f.pattern == "" && !f.dyld {
		return fmt.Errorf("--range requires --pattern or --dyld")
	}
	// Neither flag selects a target, so without one the invocation would fall
	// through to extracting the entire archive.
	if f.confirm && f.pattern == "" && !f.dyld {
		return fmt.Errorf("--confirm requires --pattern or --dyld")
	}
	if f.payloadRange != "" {
		if _, err := regexp.Compile(f.payloadRange); err != nil {
			return fmt.Errorf("invalid --range regex '%s': %w", f.payloadRange, err)
		}
	}
	if !f.dyld {
		return nil
	}
	if f.pattern != "" {
		return fmt.Errorf("cannot use --dyld with --pattern (--dyld searches for dyld_shared_cache files itself)")
	}
	// Every --dyld source preserves directory structure, so --flat can never
	// apply to it. Reject it only when no other requested extraction consumes
	// it: `--dyld --kernel --flat` wrote a flattened kernelcache before --dyld
	// reported anything, and must keep doing so.
	if f.flat && !f.kernel {
		return fmt.Errorf("--flat is not supported with --dyld (its cryptex, asset and payloadv2 sources always preserve directory structure)")
	}
	return nil
}

func validateOTAJSONArgs(f otaExtractFlags) error {
	if !f.json {
		return nil
	}
	if !f.dyld {
		return fmt.Errorf("--json requires --dyld")
	}
	if f.cryptex != "" || f.kernel || f.pattern != "" || len(f.args) == 2 {
		return fmt.Errorf("--json cannot be combined with --cryptex, --kernel, --pattern, or FILENAME")
	}
	return nil
}

func matchesPostBOMPattern(re *regexp.Regexp, name string) bool {
	// Preserve compatibility with basename-anchored patterns while also
	// supporting full-path matches.
	return re.MatchString(name) || re.MatchString(filepath.Base(name))
}

func outputPathForExtraction(outputDir, name string, flat bool) (string, error) {
	if flat {
		return filepath.Join(outputDir, filepath.Base(name)), nil
	}
	return utils.SanitizeArchivePath(outputDir, name)
}

type otaOpenable interface {
	Open(name string, decomp bool) (fs.File, error)
}

func copyOTAFileToPath(o otaOpenable, name string, decomp bool, outputPath string) error {
	ff, err := o.Open(name, decomp)
	if err != nil {
		return fmt.Errorf("failed to open file '%s' in OTA: %w", name, err)
	}
	defer ff.Close()

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Stage beside the destination and rename into place. Writing directly would
	// truncate on os.Create, so any later failure — including a failed Close,
	// which leaves a file of unverified contents behind — would destroy whatever
	// an earlier extraction source already materialized at this path. Renaming
	// means the destination only ever holds the old file or the complete new one.
	tmp, err := stageFileFor(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()        // no-op once closed below
		_ = os.Remove(tmpName) // no-op once renamed away
	}()

	if _, err := io.Copy(tmp, ff); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close output file '%s': %w", outputPath, err)
	}
	if err := os.Rename(tmpName, outputPath); err != nil {
		return fmt.Errorf("failed to move '%s' into place: %w", outputPath, err)
	}

	return nil
}

// stageFileFor creates a staging file beside outputPath carrying the mode the
// finished file must end up with, so the rename needs no chmod afterwards.
//
// The metadata contract matches a direct write: an existing destination KEEPS
// the permissions it already has, because os.Create only applies a mode when it
// creates; and a new destination gets 0666 masked by the process umask, because
// that is what os.Create requests. Hard-coding a mode here would both override a
// restrictive umask and silently widen an existing 0600 file.
func stageFileFor(outputPath string) (*os.File, error) {
	mode := os.FileMode(0o666) // O_CREATE applies the umask, as os.Create does
	preserve := false
	if fi, err := os.Stat(outputPath); err == nil {
		mode = fi.Mode().Perm()
		preserve = true
	}

	dir, base := filepath.Split(outputPath)
	for i := range 1000 {
		f, err := os.OpenFile(
			filepath.Join(dir, fmt.Sprintf(".%s.partial%d", base, i)),
			os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return nil, err
		}
		if preserve {
			// O_CREATE masked the mode with the umask; an existing destination's
			// own permissions must survive the overwrite untouched.
			if err := os.Chmod(f.Name(), mode); err != nil {
				_ = f.Close()
				_ = os.Remove(f.Name())
				return nil, err
			}
		}
		return f, nil
	}
	return nil, fmt.Errorf("no free staging name beside '%s'", outputPath)
}

func readOTAFile(o otaOpenable, name string, decomp bool) ([]byte, error) {
	ff, err := o.Open(name, decomp)
	if err != nil {
		return nil, fmt.Errorf("failed to open file '%s' in OTA: %w", name, err)
	}
	defer ff.Close()

	data, err := io.ReadAll(ff)
	if err != nil {
		return nil, fmt.Errorf("failed to read file '%s' in OTA: %w", name, err)
	}

	return data, nil
}

func resolveOutputRoot(o *ota.AA, userOutput string) (string, error) {
	i, err := o.Info()
	if err != nil {
		return "", &ota.PhaseError{Phase: ota.PhaseOTAInfo, Err: fmt.Errorf("failed to get OTA info: %v", err)}
	}
	folder, err := i.GetFolder()
	if err != nil {
		return "", &ota.PhaseError{Phase: ota.PhaseOTAInfo, Err: fmt.Errorf("failed to get OTA folder: %v", err)}
	}
	output := filepath.Join(reportRoot(userOutput), folder)
	if err := os.MkdirAll(output, 0o755); err != nil {
		return "", &ota.PhaseError{Phase: ota.PhaseOutputSetup, Err: fmt.Errorf("failed to create output directory: %v", err)}
	}
	return output, nil
}

// reportRoot is the base every dscFileEntry.Path is relative to.
func reportRoot(userOutput string) string {
	if userOutput == "" {
		return "."
	}
	return userOutput
}

// reportPreExtractFailure emits a report for failures that happen before any
// extraction can start, so a JSON caller always gets a document to parse.
func reportPreExtractFailure(w io.Writer, f otaExtractFlags, phase ota.Phase, err error) error {
	if !f.json {
		return err
	}
	if werr := writeDSCReport(w, failedDSCReport(phase, err)); werr != nil {
		return errors.Join(err, werr)
	}
	return err
}

// dscPrompt returns the payloadv2 consent prompt, or nil when the invocation
// already carries consent and must never block on a terminal.
func dscPrompt(f otaExtractFlags) func(string) bool {
	if f.json || f.confirm {
		return nil
	}
	return confirmPayloadSearch
}

func runDyldExtract(f otaExtractFlags, o *ota.AA, output string, w io.Writer) error {
	rep := extractDSC(otaDSCSource{AA: o, decomp: f.decomp}, dscOptions{
		Output:       output,
		ReportRoot:   reportRoot(f.output),
		PayloadRange: f.payloadRange,
		Arches:       f.dyldArches,
		Prompt:       dscPrompt(f),
	})
	logDSCReport(reportRoot(f.output), rep)
	if f.json {
		if err := writeDSCReport(w, rep); err != nil {
			return err
		}
		if !rep.Complete {
			return fmt.Errorf(
				"dyld_shared_cache extraction incomplete: %d error(s); see JSON report on stdout",
				len(rep.Errors))
		}
		return nil
	}
	// fatalErr already drops the "searched everywhere, found nothing" sentinel,
	// which is the only case human mode is allowed to call a success. A real
	// source failure still propagates even when other sources produced files:
	// before the report existed, a failing asset copy or payloadv2 scan returned
	// its error straight out of RunE, and scripts still depend on that.
	return rep.fatalErr()
}

func logRelative(cwd, fname string) {
	if rel, err := filepath.Rel(cwd, fname); err != nil {
		utils.Indent(log.Info, 2)(fname)
	} else {
		utils.Indent(log.Info, 2)(rel)
	}
}

func extractCryptexDMG(o *ota.AA, cryptex, output, cwd string) error {
	log.Infof("Extracting %s Cryptex", cryptex)
	out, err := o.ExtractCryptex(cryptex, output)
	if err != nil {
		return fmt.Errorf("failed to extract %s cryptex: %v", cryptex, err)
	}
	logRelative(cwd, out)
	return nil
}

func extractKernelcaches(o *ota.AA, output string, flat bool, cwd string) error {
	log.Info("Extracting kernelcache(s)")
	re := regexp.MustCompile(`kernelcache.*$`)
	for _, f := range o.Files() { // search in OTA asset files
		if f.IsDir() || !re.MatchString(f.Name()) {
			continue
		}
		if err := extractKernelcache(o, f.Name(), output, flat, cwd); err != nil {
			return err
		}
	}
	return nil
}

func extractKernelcache(o *ota.AA, name, output string, flat bool, cwd string) error {
	data, err := readOTAFile(o, name, false)
	if err != nil {
		return fmt.Errorf("failed to read kernelcache: %v", err)
	}
	comp, err := kernelcache.ParseImg4Data(data)
	if err != nil {
		return fmt.Errorf("failed to parse kernelcache: %v", err)
	}
	kdata, err := kernelcache.DecompressData(comp)
	if err != nil {
		return fmt.Errorf("failed to parse kernelcache compressed data: %v", err)
	}
	fname, err := outputPathForExtraction(output, name, flat)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}
	logRelative(cwd, fname)
	if err := os.WriteFile(fname, kdata, 0o644); err != nil {
		return fmt.Errorf("failed to write kernelcache: %v", err)
	}
	return nil
}

func extractByPattern(o *ota.AA, f otaExtractFlags, output string) error {
	re, err := regexp.Compile(f.pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex pattern '%s': %v", f.pattern, err)
	}
	log.WithField("pattern", re.String()).Info("Extracting Files Matching Pattern")
	if err := extractPatternAssets(o, f, re, output); err != nil {
		return err
	}
	return extractPatternPayloads(o, f, re, output)
}

func extractPatternAssets(o *ota.AA, f otaExtractFlags, re *regexp.Regexp, output string) error {
	for _, file := range o.Files() { // search in OTA asset files
		if file.IsDir() || !matchesPostBOMPattern(re, file.Name()) {
			continue
		}
		fname, err := outputPathForExtraction(output, file.Name(), f.flat)
		if err != nil {
			return err
		}
		utils.Indent(log.Info, 2)(fname)
		if err := copyOTAFileToPath(o, file.Name(), f.decomp, fname); err != nil {
			return err
		}
	}
	return nil
}

func extractPatternPayloads(o *ota.AA, f otaExtractFlags, re *regexp.Regexp, output string) error {
	bomFound := false
	for _, file := range o.PostFiles() { // search in OTA post.bom files
		if file.IsDir() || !matchesPostBOMPattern(re, file.Name()) {
			continue
		}
		utils.Indent(log.Warn, 2)(fmt.Sprintf("Found '%s' in post.bom (most likely in payloadv2 files)", filepath.Base(file.Name())))
		bomFound = true
	}
	if !bomFound {
		return nil
	}
	if !f.confirm && !confirmPayloadSearch(fmt.Sprintf("Search for '%s' in payloadv2 files?", re.String())) {
		return nil
	}
	utils.Indent(log.Info, 2)(fmt.Sprintf("Searching for '%s' in OTA payload files", re.String()))
	return o.GetPayloadFiles(f.pattern, f.payloadRange, output)
}

func extractAllFiles(o *ota.AA, f otaExtractFlags, output string) error {
	log.Info("Extracting all files from OTA")
	for _, file := range o.Files() {
		if file.IsDir() {
			continue
		}
		fname, err := outputPathForExtraction(output, file.Name(), f.flat)
		if err != nil {
			return err
		}
		if _, err := os.Stat(fname); err == nil {
			log.Warnf("already exists: '%s' ", fname)
			continue
		}
		utils.Indent(log.Info, 2)(fname)
		if err := copyOTAFileToPath(o, file.Name(), f.decomp, fname); err != nil {
			return err
		}
	}
	return nil
}

func extractSingleFile(o *ota.AA, f otaExtractFlags, output string) error {
	name := filepath.Clean(f.args[1])
	fname := filepath.Join(output, name)
	log.Infof("Extracting to '%s'", fname)
	return copyOTAFileToPath(o, name, f.decomp, fname)
}

func runOTAExtract(w io.Writer, f otaExtractFlags, o *ota.AA, output string) error {
	if f.targeted() {
		return runTargetedExtract(w, f, o, output)
	}
	if len(f.args) > 1 {
		return extractSingleFile(o, f, output)
	}
	return extractAllFiles(o, f, output)
}

// targetedExtracts holds the extractions one invocation asked for. A field is
// nil when its flag was not given.
type targetedExtracts struct {
	cryptex func() error
	dyld    func() error
	kernel  func() error
	pattern func() error
}

// run performs each requested extraction in order. dyld is the only step whose
// failure does not cancel the steps after it: before --dyld reported failures
// at all, `--dyld --kernel` still extracted the kernelcache, and scoping the
// new non-zero exit to --json means human mode must keep doing so.
func (t targetedExtracts) run() error {
	if t.cryptex != nil {
		if err := t.cryptex(); err != nil {
			return err
		}
	}
	var dyldErr error
	if t.dyld != nil {
		dyldErr = t.dyld()
	}
	if t.kernel != nil {
		if err := t.kernel(); err != nil {
			return errors.Join(dyldErr, err)
		}
	}
	if t.pattern != nil {
		return errors.Join(dyldErr, t.pattern())
	}
	return dyldErr
}

func runTargetedExtract(w io.Writer, f otaExtractFlags, o *ota.AA, output string) error {
	cwd, _ := os.Getwd()
	var t targetedExtracts
	if f.cryptex != "" {
		t.cryptex = func() error { return extractCryptexDMG(o, f.cryptex, output, cwd) }
	}
	if f.dyld {
		t.dyld = func() error { return runDyldExtract(f, o, output, w) }
	}
	if f.kernel {
		t.kernel = func() error { return extractKernelcaches(o, output, f.flat, cwd) }
	}
	if f.pattern != "" {
		t.pattern = func() error { return extractByPattern(o, f, output) }
	}
	return t.run()
}

func init() {
	OtaCmd.AddCommand(otaExtractCmd)

	otaExtractCmd.Flags().StringP("cryptex", "c", "", "Extract cryptex as DMG (requires full OTA)")
	otaExtractCmd.RegisterFlagCompletionFunc("cryptex", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return validCryptexes, cobra.ShellCompDirectiveDefault
	})
	otaExtractCmd.Flags().BoolP("dyld", "d", false, "Extract dyld_shared_cache files")
	otaExtractCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture(s) to extract (requires --dyld)")
	otaExtractCmd.RegisterFlagCompletionFunc("dyld-arch", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return dyld.DscArches, cobra.ShellCompDirectiveDefault
	})
	otaExtractCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache")
	otaExtractCmd.Flags().StringP("pattern", "p", "", "Regex pattern to match files")
	otaExtractCmd.Flags().StringP("range", "r", "", "Regex pattern to limit payloadv2 files searched (requires --pattern or --dyld)")
	otaExtractCmd.Flags().BoolP("confirm", "y", false, "Skip prompt and search payloadv2 files (requires --pattern or --dyld)")
	otaExtractCmd.Flags().BoolP("json", "j", false, "Output a single JSON dyld_shared_cache extraction report to stdout (requires --dyld)")
	otaExtractCmd.Flags().BoolP("decomp", "x", false, "Decompress pbzx files")
	otaExtractCmd.Flags().BoolP("flat", "f", false, "Do NOT preserve directory structure when extracting")
	otaExtractCmd.Flags().StringP("output", "o", "", "Output folder")
	otaExtractCmd.MarkFlagDirname("output")
	viper.BindPFlag("ota.extract.cryptex", otaExtractCmd.Flags().Lookup("cryptex"))
	viper.BindPFlag("ota.extract.dyld", otaExtractCmd.Flags().Lookup("dyld"))
	viper.BindPFlag("ota.extract.dyld-arch", otaExtractCmd.Flags().Lookup("dyld-arch"))
	viper.BindPFlag("ota.extract.kernel", otaExtractCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("ota.extract.pattern", otaExtractCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("ota.extract.range", otaExtractCmd.Flags().Lookup("range"))
	viper.BindPFlag("ota.extract.confirm", otaExtractCmd.Flags().Lookup("confirm"))
	viper.BindPFlag("ota.extract.json", otaExtractCmd.Flags().Lookup("json"))
	viper.BindPFlag("ota.extract.decomp", otaExtractCmd.Flags().Lookup("decomp"))
	viper.BindPFlag("ota.extract.flat", otaExtractCmd.Flags().Lookup("flat"))
	viper.BindPFlag("ota.extract.output", otaExtractCmd.Flags().Lookup("output"))
}

// otaExtractCmd represents the extract command
var otaExtractCmd = &cobra.Command{
	Use:     "extract <OTA> [FILENAME]",
	Aliases: []string{"e"},
	Short:   "Extract OTA payload files",
	Example: heredoc.Doc(`
		# Extract the dyld_shared_cache files from an OTA
		❯ ipsw ota extract OTA.zip --dyld --output ./out
		# Same, but non-interactive with a machine-readable report on stdout
		❯ ipsw ota extract OTA.zip --dyld --json --output ./out > report.json
		# Extract only arm64e cache-family files
		❯ ipsw ota extract OTA.zip --dyld --dyld-arch arm64e --output ./out
		# Extract the kernelcache, flattening the output directory structure
		❯ ipsw ota extract OTA.zip --kernel --flat --output ./out
		# Extract every file matching a regex, limited to some payloadv2 members
		❯ ipsw ota extract OTA.zip --pattern 'AppleH1[0-9]CameraInterface' --range 'payload.0[0-3]\d' --confirm`),
	Args:          cobra.RangeArgs(1, 2),
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		f := otaExtractFlagsFromViper(args)
		if err := validateOTAExtractArgs(f); err != nil {
			return err
		}
		if f.cryptex != "" && !slices.Contains(validCryptexes, f.cryptex) {
			return fmt.Errorf("invalid --cryptex: '%s' (must be one of: %s)", f.cryptex, strings.Join(validCryptexes, ", "))
		}

		stdout := cmd.OutOrStdout()
		o, err := ota.Open(filepath.Clean(args[0]), ResolveAEAKeyFromFlags(args[0]))
		if err != nil {
			return reportPreExtractFailure(stdout, f, ota.PhaseOTAOpen,
				fmt.Errorf("failed to open OTA file: %w", err))
		}
		defer o.Close()

		output, err := resolveOutputRoot(o, f.output)
		if err != nil {
			return reportPreExtractFailure(stdout, f, ota.PhaseOTAInfo, err)
		}

		return runOTAExtract(stdout, f, o, output)
	},
}
