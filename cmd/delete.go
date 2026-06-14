package cmd

import (
	"credman/internal/vault"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewDeleteCmd(manager *vault.VaultManager) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "delete credential",
		Long: `Delete credential from the vault

Examples:
  credman delete github 
  credman delete api`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			pw, err := PromptPassword("Password: ")
			if err != nil {
				return err
			}
			v, err := manager.UnlockVault([]byte(pw))
			if err != nil {
				return err
			}

			err = v.DeleteByName(name)
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Credential %q deleted successfully\n", name)
			return nil
		},
	}

	return cmd
}
