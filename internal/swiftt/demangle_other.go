//go:build !darwin

package swift

func Demangle(input string) (string, error) {
	return "", nil // this is a no-op on non-darwin platforms
}
func DemangleSimple(input string) (string, error) {
	return "", nil // this is a no-op on non-darwin platforms
}
