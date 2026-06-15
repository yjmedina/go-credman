package cmd

import (
	"credman/internal/vault"
	"fmt"
	"strings"
)

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
