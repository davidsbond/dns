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
		Use:   "serve [config-file]",
		Short: "Run the DNS server",
		Example: `
# Start with default configuration
dns serve

# Start with a configuration file.
dns serve config.toml`,
		Long: `Starts the DNS server based on the provided configuration file.

If no configuration file is specified, the server will handle unencrypted DNS requests on port 53 across all interfaces 
for both TCP and UDP, upstreaming to Cloudflare DNS. 

For more information on configuration (DoT, DoH etc.) see the documentation at https://github.com/davidsbond/dns.`,
		Args: cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			config := server.DefaultConfig()

			if len(args) > 0 {
				config, err = server.LoadConfig(args[0])
				if err != nil {
					return fmt.Errorf("failed to load configuration file: %w", err)
				}
			}

			return server.Run(cmd.Context(), config)
		},
	}
}
