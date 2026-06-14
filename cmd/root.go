package cmd

import (
	"fmt"
	"os"

	"credman/internal/vault"

	"github.com/spf13/cobra"
)

func NewRootCommand() (*cobra.Command, error) {

	var rootCmd = &cobra.Command{
		Use:           "credman",
		Short:         "CLI to manage your credentials",
		Long:          `A CLI to keep your credentials in a single place and secure`,
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	manager, err := vault.NewVaultManager()
	if err != nil {
		return nil, fmt.Errorf("could not create manager: %w", err)
	}

	rootCmd.AddCommand(NewInitCmd(manager))
	rootCmd.AddCommand(NewAddCmd(manager))
	rootCmd.AddCommand(NewSearchCmd(manager))

	return rootCmd, nil
}

func Execute() {
	rootCmd, err := NewRootCommand()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1) // cobra already printed the error
	}
}
