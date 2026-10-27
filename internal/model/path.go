package model

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// ValidateRelativePath validates a logical destination using Windows rules on
// every host. It returns slash separators. This is lexical validation only;
// privileged IO must separately check containment and reparse points.
func ValidateRelativePath(value string) (string, error) {
	if value == "" || !utf8.ValidString(value) {
		return "", fmt.Errorf("relative path must be nonempty UTF-8")
	}
	value = strings.ReplaceAll(value, `\`, "/")
	if strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("relative path must not be absolute or UNC")
	}
	for _, r := range value {
		if r < 32 || strings.ContainsRune(`:<>"|?*`, r) {
			return "", fmt.Errorf("relative path contains a forbidden Windows character")
		}
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("relative path contains an empty or traversal component")
		}
		if strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", fmt.Errorf("relative path component ends with a dot or space")
		}
		base, _, _ := strings.Cut(part, ".")
		// Windows also recognizes a device base padded before an extension.
		base = strings.ToUpper(strings.TrimRight(base, " "))
		device := base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$" || base == "CLOCK$"
		for _, prefix := range []string{"COM", "LPT"} {
			if suffix, ok := strings.CutPrefix(base, prefix); ok && strings.Contains("123456789¹²³", suffix) && len([]rune(suffix)) == 1 {
				device = true
			}
		}
		if device {
			return "", fmt.Errorf("relative path contains a reserved Windows device name")
		}
	}
	return value, nil
}
