package cmd

import (
	"credman/internal/vault"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewEditCmd(manager *vault.VaultManager) *cobra.Command {
	var (
		vars      []string
		secrets   []string
		deletions []string
		rename    string
	)

	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Modify, delete, or rename a credential's fields",
		Long: `Edit the credential <name>. Any combination of the following can be
applied in a single call:

  -v key=value   set or replace a plain field
  -s key         set or replace a secret field, prompted hidden
  -d key         delete an existing field by name
  --rename NAME  rename the credential itself

It is an error to set and delete the same field name in one call, to
delete a field that does not exist, or to rename to a name already
used by another credential.

Examples:
  credman edit github -v user=alice
  credman edit github -s password
  credman edit github -d old_field
  credman edit github --rename github-personal
  credman edit github -v user=alice -d old_field --rename github-personal`,
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

			creds, err := v.Edit(vault.EditCredential{
				Name:      name,
				NewName:   rename,
				Fields:    fields,
				Deletions: deletions,
			})
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Updated credential %q\n", creds.Name)
			return nil
		},
	}

	cmd.Flags().StringArrayVarP(&vars, "var", "v", nil, "Inline field key=value (repeatable)")
	cmd.Flags().StringArrayVarP(&secrets, "secret", "s", nil, "Prompt for this field's value, hidden (repeatable)")
	cmd.Flags().StringArrayVarP(&deletions, "delete", "d", nil, "Field name to delete (repeatable)")
	cmd.Flags().StringVar(&rename, "rename", "", "Rename credential to this new name")

	return cmd
}
