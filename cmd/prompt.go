package cmd

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// PromptPassword reads a password from the terminal without echoing it.
// The prompt is written to stderr so it stays out of piped stdout.
func PromptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(pw), nil
}

// PromptNewPassword prompts twice and verifies the entries match.
// Use this when creating or rotating a vault password.
func PromptNewPassword(prompt, confirm string) (string, error) {
	pw1, err := PromptPassword(prompt)
	if err != nil {
		return "", err
	}
	pw2, err := PromptPassword(confirm)
	if err != nil {
		return "", err
	}
	if pw1 != pw2 {
		return "", errors.New("passwords do not match")
	}
	return pw1, nil
}
