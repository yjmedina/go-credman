package cmd

import (
	"fmt"
	"os"

	"credman/internal/vault"

	"github.com/spf13/cobra"
)

func NewRootCommand() (*cobra.Command, error) {

	var rootCmd = &cobra.Command{
		Use:   "credman",
		Short: "Manage local credentials in an encrypted vault",
		Long: `Credman stores, retrieves, and edits credentials in a local vault
encrypted with a master password.

Every command (except "init") unlocks the vault by prompting for the
master password. Run "credman init" once to create the vault before
using any other command.`,
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
	rootCmd.AddCommand(NewGetCmd(manager))
	rootCmd.AddCommand(NewDeleteCmd(manager))
	rootCmd.AddCommand(NewEditCmd(manager))

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
