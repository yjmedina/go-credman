package cmd

import (
	"credman/internal/vault"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewInitCmd(manager *vault.VaultManager) *cobra.Command {

	var initCmd = &cobra.Command{
		Use:   "init",
		Short: "Init the Credential Manager Database",
		Long:  "Run the setup of the database and create your first vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			// init flow
			pw, err := PromptNewPassword("New password: ", "Confirm: ")
			if err != nil {
				return err
			}
			err = manager.Init([]byte(pw))
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Credman init succesfully.")
			return nil

		},
	}

	return initCmd
}
