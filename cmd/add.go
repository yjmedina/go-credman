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

func parseVariable(kv string) (vault.NamedField, error) {
	idx := strings.IndexByte(kv, '=')
	if idx <= 0 {
		return vault.NamedField{}, fmt.Errorf("invalid field %q: expected key=value", kv)
	}
	return vault.NamedField{
		Name:      kv[:idx],
		Value:     kv[idx+1:],
		Sensitive: false,
	}, nil
}

func readSecretField(key string) (vault.NamedField, error) {
	if key == "" {
		return vault.NamedField{}, fmt.Errorf("--secret requires a field name")
	}
	val, err := PromptPassword(fmt.Sprintf("Enter value for secret [%s]: ", key))
	if err != nil {
		return vault.NamedField{}, err
	}
	return vault.NamedField{Name: key, Value: val, Sensitive: true}, nil
}

func parseVariablesAndSecrets(variables []string, secrets []string) ([]vault.NamedField, error) {
	out := make([]vault.NamedField, 0, len(variables)+len(secrets))
	seen := make(map[string]struct{}, len(variables)+len(secrets))

	for _, variable := range variables {
		field, err := parseVariable(variable)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[field.Name]; dup {
			return nil, fmt.Errorf("duplicate field name: %q", field.Name)
		}
		seen[field.Name] = struct{}{}
		out = append(out, field)
	}

	for _, secret := range secrets {
		if _, dup := seen[secret]; dup {
			return nil, fmt.Errorf("duplicate field name: %q", secret)
		}
		field, err := readSecretField(secret)
		if err != nil {
			return nil, err
		}
		seen[field.Name] = struct{}{}
		out = append(out, field)
	}

	return out, nil
}
