// Package main provides the entrypoint to the dns binary.
//
//go:generate ./scripts/refresh_licenses.sh
package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/davidsbond/dns/cmd/serve"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	defer cancel()

	cmd := &cobra.Command{
		Use:   "dns",
		Short: "An opinionated, ad-blocking DNS server",
		Long: `This binary runs a forwarding DNS server that contains a built-in block and allow lists for known tracking 
domains.

Lists are obtained from https://github.com/hagezi/dns-blocklists and embedded directly into the binary at build-time.`,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		cmd.Version = info.Main.Version
	}

	cmd.AddCommand(
		serve.Command(),
	)

	if err := cmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
