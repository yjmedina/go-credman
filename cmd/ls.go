package cmd

import (
	"credman/internal/vault"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewLsCmd(manager *vault.VaultManager) *cobra.Command {
	var (
		pattern string
	)

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List credentials, optionally filtered by name",
		Long: `List the names of credentials stored in the vault.

With no flags, every credential is listed in alphabetical order.
With -p/--pattern, only credentials whose name contains the given
substring are returned (case-sensitive, no wildcards needed).

Only names are returned — use "credman get <name>" to view fields.

Examples:
  credman ls
  credman ls -p dev
  credman ls -p github`,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := manager.LockVault()
			if err != nil {
				return err
			}

			credentialNames, err := v.ListNames(pattern)
			if err != nil {
				return err
			}

			for _, cred := range credentialNames {
				fmt.Fprintf(os.Stdout, "%s\n", cred)

			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&pattern, "pattern", "p", "", "Search pattern")

	return cmd
}
