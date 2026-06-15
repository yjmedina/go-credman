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
		Short: "Delete a credential from the vault",
		Long: `Permanently remove the credential <name> from the vault, including
all of its fields. This operation cannot be undone.

If no credential with that name exists, the command exits with an error.

Examples:
  credman delete github
  credman delete api-backend-dev`,
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
