package storeauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrNativeUnavailable reports that this platform cannot provide the native
// Apple frameworks required for App Store authentication.
var ErrNativeUnavailable = errors.New("native App Store authentication is unavailable")

const (
	nativeSignTimeout       = 20 * time.Second
	maxNativeSigningBody    = 4 << 20
	maxNativeSignatureBytes = 64 << 10
	maxNativeHeadersBytes   = 32 << 10
	maxNativeHeaderBytes    = 8 << 10
)

// NativeSupported reports whether the native anisette and signing framework
// classes are available. It does not establish that their operations succeed.
func NativeSupported() bool {
	return nativeSupported()
}

// NativeHeaders produces a fresh set of anisette headers from macOS. The
// framework operation is synchronous; cancellation is checked before and after
// it so a canceled operation never returns device headers.
func NativeHeaders(ctx context.Context) (http.Header, error) {
	if err := nativeContextError(ctx); err != nil {
		return nil, err
	}
	data, err := nativeHeaderData()
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, err
	}
	return decodeNativeHeaders(data)
}

// Sign returns the native Mescal signature of exactly body. Apple's synchronous
// promise wait is limited to 20 seconds or the remaining context deadline.
// Cancellation during that wait is observed before a signature is returned.
func Sign(ctx context.Context, body []byte) ([]byte, error) {
	wait, err := nativeSignWait(ctx)
	if err != nil {
		return nil, err
	}
	if len(body) > maxNativeSigningBody {
		return nil, errors.New("native App Store signing body exceeds the size limit")
	}
	signature, err := nativeSign(body, wait)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 || len(signature) > maxNativeSignatureBytes {
		return nil, errors.New("native App Store signing returned an invalid signature")
	}
	return signature, nil
}

func nativeContextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("native App Store authentication requires a context")
	}
	return ctx.Err()
}

func nativeSignWait(ctx context.Context) (time.Duration, error) {
	if err := nativeContextError(ctx); err != nil {
		return 0, err
	}
	wait := nativeSignTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, context.DeadlineExceeded
		}
		if remaining < wait {
			wait = remaining
		}
	}
	return wait, nil
}

func decodeNativeHeaders(data []byte) (http.Header, error) {
	invalid := errors.New("native anisette headers are invalid")
	if len(data) == 0 || len(data) > maxNativeHeadersBytes {
		return nil, invalid
	}
	var values map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, invalid
	}
	names := [...]string{
		"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO",
		"X-Apple-I-MD-LU", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone",
		"X-Apple-Locale", "X-Mme-Device-Id", "X-Apple-I-SRL-NO",
		"X-MMe-Client-Info",
	}
	if len(values) != len(names) {
		return nil, invalid
	}
	headers := make(http.Header, len(names))
	for _, name := range names {
		value, ok := values[name]
		if !ok || (value == "" && name != "X-Apple-I-MD-LU") || len(value) > maxNativeHeaderBytes {
			return nil, invalid
		}
		for _, character := range value {
			if character < 0x20 && character != '\t' || character == 0x7f {
				return nil, invalid
			}
		}
		headers.Set(name, value)
	}
	return headers, nil
}

func nativeFailure(operation, domain string, code int64) error {
	for _, character := range domain {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			domain = ""
			break
		}
	}
	if len(domain) > 127 {
		domain = ""
	}
	if domain == "" {
		return fmt.Errorf("native App Store %s failed", operation)
	}
	return fmt.Errorf("native App Store %s failed (domain=%s code=%d)", operation, domain, code)
}
