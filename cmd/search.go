package cmd

import (
	"credman/internal/vault"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewSearchCmd(manager *vault.VaultManager) *cobra.Command {
	var (
		pattern string
	)

	cmd := &cobra.Command{
		Use:   "search <pattern>",
		Short: "Search for credentials",
		Long: `Search for credentials.

Examples:
  credman search
  credman search -pattern -dev 
  `,
		RunE: func(cmd *cobra.Command, args []string) error {
			pw, err := PromptPassword("password: ")
			if err != nil {
				return err
			}
			v, err := manager.UnlockVault([]byte(pw))
			if err != nil {
				return err
			}

			credentialNames, err := v.Search(pattern)
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
