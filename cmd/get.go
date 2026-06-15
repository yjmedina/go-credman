package cmd

import (
	"credman/internal/vault"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewGetCmd(manager *vault.VaultManager) *cobra.Command {
	var (
		showSecrets bool
	)

	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Show the fields of a credential",
		Long: `Print every field of the credential <name>, one per line, in
"key: value" form.

Sensitive fields are masked by default. Pass -s/--show to reveal them
in plaintext — useful for piping into another tool, but be mindful of
shell history and screen sharing.

Examples:
  credman get github
  credman get github -s
  credman get api-backend-dev`,
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
			creds, err := v.GetByName(name)
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stdout, "%s\n", creds.Name)

			for _, name := range creds.GetFieldNames() {
				field := creds.Fields[name]
				value := field.Value
				if field.Sensitive && !showSecrets {
					value = "***********"
				}
				fmt.Fprintf(os.Stdout, "%s: %s\n", name, value)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&showSecrets, "show", "s", false, "show the value of senstive credentials")
	return cmd
}
