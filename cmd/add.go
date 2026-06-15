package cmd

import (
	"credman/internal/vault"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewAddCmd(manager *vault.VaultManager) *cobra.Command {
	var (
		vars    []string
		secrets []string
	)

	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a new credential to the vault",
		Long: `Add a new credential identified by <name>. The name must be unique
within the vault.

Fields are passed with repeatable flags:
  -v key=value   plain field, value visible on the command line
  -s key         secret field, value is prompted for and hidden

A credential can have any combination of plain and secret fields.

Examples:
  credman add github -v user=alice -s password
  credman add github -v user=alice -v url=https://github.com -s password
  credman add api -v owner=team -s token -s backup_token`,
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

			fields, err := parseVariablesAndSecrets(vars, secrets)
			if err != nil {
				return err
			}

			creds, err := v.New(vault.NewCredential{
				Name:   name,
				Fields: fields,
			})
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Added credential %q\n", creds.Name)
			return nil
		},
	}

	cmd.Flags().StringArrayVarP(&vars, "var", "v", nil, "Inline field key=value (repeatable)")
	cmd.Flags().StringArrayVarP(&secrets, "secret", "s", nil, "Prompt for this field's value, hidden (repeatable)")

	return cmd
}
