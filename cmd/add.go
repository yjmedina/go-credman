package cmd

import (
	"credman/internal/vault"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func NewAddCmd(manager *vault.VaultManager) *cobra.Command {
	var (
		vars    []string
		secrets []string
	)

	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a new credential",
		Long: `Add a new credential to the vault.

Examples:
  credman add github -v user=alice -s password
  credman add github -v user=alice -v url=https://github.com -s password
  credman add api -v owner=team -s token -s backup_token`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			inlineFields, err := parseKVFields(vars)
			if err != nil {
				return err
			}

			pw, err := PromptPassword("Password: ")
			if err != nil {
				return err
			}
			v, err := manager.UnlockVault([]byte(pw))
			if err != nil {
				return err
			}

			secretFields, err := readSecretFields(secrets)
			if err != nil {
				return err
			}

			credFields := make([]vault.Field, 0, len(inlineFields)+len(secretFields))
			credFields = append(credFields, inlineFields...)
			credFields = append(credFields, secretFields...)

			creds, err := v.New(vault.NewCredential{
				Name:   name,
				Fields: credFields,
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

func parseKVFields(raw []string) ([]vault.Field, error) {
	out := make([]vault.Field, 0, len(raw))
	for _, kv := range raw {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			return nil, fmt.Errorf("invalid field %q: expected key=value", kv)
		}
		out = append(out, vault.Field{
			Name:  kv[:idx],
			Value: kv[idx+1:],
		})
	}
	return out, nil
}

func readSecretFields(keys []string) ([]vault.Field, error) {
	out := make([]vault.Field, 0, len(keys))
	for _, key := range keys {
		if key == "" {
			return nil, fmt.Errorf("--secret requires a field name")
		}
		val, err := PromptPassword(fmt.Sprintf("Enter value for secret [%s]: ", key))
		if err != nil {
			return nil, err
		}
		out = append(out, vault.Field{
			Name:      key,
			Value:     val,
			Sensitive: true,
		})
	}
	return out, nil
}
