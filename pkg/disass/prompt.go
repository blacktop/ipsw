package disass

import (
	"bytes"
	"strings"

	"text/template"
)

const promptTemplate = `
You are an expert reverse engineer specializing in AARCH64/ARM64 assembly on the Apple platform.
Analyze the following AARCH64/ARM64 assembly function and provide its equivalent {{ .Language }} pseudo-code.
Focus on accuracy, readability, and standard {{ .Language }} conventions.
Respond ONLY with the {{ .Language }} code block. Do not include explanations, markdown formatting, or any text outside the code.
Simplify logic where possible (e.g., convert complex addressing modes or bitwise operations into clearer {{ .Language }} expressions).
Use descriptive variable and function names based on context, if possible.
If the assembly includes standard library calls (heuristically identifiable), represent them with appropriate {{ .Language }} function calls.
Handle common AARCH64/ARM64 patterns like function prologues/epilogues correctly (e.g., setting up/tearing down stack frames).
Convert assembly control flow (branches, conditional branches) into {{ .Language }} control flow (if/else, loops, goto if necessary but prefer structured flow).
If string literals or constants are clearly loaded into registers (e.g., from comments like '; "STRING"' or immediate loads), use them in the {{ .Language }} code.
Assembly:

%s`

func GetPrompt(content string, lang string) (string, string, error) {
	var tmptout bytes.Buffer
	var lexer string
	if lang != "" {
		switch strings.ToLower(lang) {
		case "swift":
			lang = "Swift"
			lexer = "swift"
		case "objc":
			lang = "Objective-C"
			lexer = "objc"
		case "c":
			lang = "C"
			lexer = "c"
		default:
			lexer = strings.ToLower(lang)
		}
	} else { // autodetect
		// TODO: add better language checks
		if content != "" {
			if strings.Contains(strings.ToLower(content), "swift_") {
				lang = "Swift"
				lexer = "swift"
			} else if strings.Contains(strings.ToLower(content), "_objc_") {
				lang = "Objective-C"
				lexer = "objc"
			} else {
				lang = "C"
				lexer = "c"
			}
		}
	}
	tmpl := template.Must(template.New("prompt").Parse(promptTemplate))
	if err := tmpl.Execute(&tmptout, map[string]string{
		"Language": lang,
	}); err != nil {
		return "", "", err
	}
	return tmptout.String(), lexer, nil
}
