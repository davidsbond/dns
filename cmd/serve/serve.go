// Package serve provides the CLI endpoint to the "serve" command.
package serve

import (
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/davidsbond/dns/internal/server"
)

// Command returns the "serve" command used to start and run the DNS server.
func Command() *cobra.Command {
	var (
		addr      string
		upstreams []string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the DNS server",
		Example: `
# Upstream to Google
dns serve --upstreams 8.8.8.8:53,8.8.4.4:53

# Upstream to Cloudflare
dns serve --upstreams 1.1.1.1:53,1.0.0.1:53`,
		RunE: func(cmd *cobra.Command, args []string) error {
			config := server.Config{
				Addr:      addr,
				Upstreams: upstreams,
				Logger:    slog.Default(),
			}

			return server.Run(cmd.Context(), config)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&addr, "addr", "0.0.0.0:53", "bind address for serving DNS requests")
	flags.StringSliceVar(&upstreams, "upstreams", []string{"8.8.8.8:53", "8.8.4.4:53"}, "upstream DNS servers")

	return cmd
}
