// Package server provides the Run function used to start the DNS server.
package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/davidsbond/dns/internal/api"
	"github.com/davidsbond/dns/internal/list"
)

type (
	// The Config type exposes fields used for configuration of the DNS server.
	Config struct {
		// The bind address of the DNS server.
		Addr string
		// The desired upstream DNS servers, each address must include a port.
		Upstreams []string
		// The logger to use for DNS resolution errors.
		Logger *slog.Logger
	}
)

// Run the DNS server.
func Run(ctx context.Context, config Config) error {
	allow, err := list.Allow(ctx)
	if err != nil {
		return fmt.Errorf("failed to load allow list: %w", err)
	}

	block, err := list.Block(ctx)
	if err != nil {
		return fmt.Errorf("failed to load block list: %w", err)
	}

	server := &dns.Server{
		Addr:    config.Addr,
		Net:     "udp",
		Handler: api.NewDNSAPI(allow, block, config.Upstreams, config.Logger),
	}

	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return server.ListenAndServe()
	})

	group.Go(func() error {
		<-ctx.Done()
		return server.Shutdown()
	})

	return group.Wait()
}
