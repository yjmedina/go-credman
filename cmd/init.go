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
		Short: "Create the vault and set the master password",
		Long: `Initialize a new vault on this machine. You'll be prompted to choose
and confirm a master password — this password is required to unlock the
vault for every other command, so make sure it's something you'll
remember. There is no recovery if it's lost.

Run this once per machine. Running init when a vault already exists
will fail.

Examples:
  credman init`,
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
