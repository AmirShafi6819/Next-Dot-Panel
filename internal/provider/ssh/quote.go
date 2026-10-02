package sshprovider

import "strings"

// safeShellChars are the characters that never need quoting in POSIX shells.
// Anything else is wrapped in single quotes, with embedded single quotes
// escaped as '\”.
const safeShellChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"

// shellQuote renders one argument as a single POSIX shell word. The SSH exec
// channel hands the server a single string, so every argument must be quoted;
// this is the only place a command string is assembled (Design Spec §9.3).
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !strings.ContainsRune(safeShellChars, r)
	}) == -1 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
