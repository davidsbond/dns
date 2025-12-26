// Package serve provides the CLI endpoint to the "serve" command.
package serve

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/davidsbond/dns/internal/server"
)

// Command returns the "serve" command used to start and run the DNS server.
func Command() *cobra.Command {
	return &cobra.Command{
		Use:     "serve <config-file>",
		Short:   "Run the DNS server",
		Example: "dns serve config.toml",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := server.LoadConfig(args[0])
			if err != nil {
				return fmt.Errorf("failed to load configuration file: %w", err)
			}

			return server.Run(cmd.Context(), config)
		},
	}
}
