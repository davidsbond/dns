// Package server provides the Run function used to start the DNS server.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"

	"github.com/davidsbond/dns/internal/cache"
	"github.com/davidsbond/dns/internal/handler"
	"github.com/davidsbond/dns/internal/list"
)

func init() {
	handler.RegisterMetrics(prometheus.DefaultRegisterer)
	cache.RegisterMetrics(prometheus.DefaultRegisterer)
	list.RegisterMetrics(prometheus.DefaultRegisterer)
}

// Run the DNS server.
func Run(ctx context.Context, config Config) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid server configuration: %w", err)
	}

	allow, err := list.Allow(ctx)
	if err != nil {
		return fmt.Errorf("failed to load allow list: %w", err)
	}

	block, err := list.Block(ctx)
	if err != nil {
		return fmt.Errorf("failed to load block list: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	var c handler.Cache = cache.NewNoopCache()
	if config.DNS.Cache != nil {
		rc := cache.NewRistrettoCache(config.DNS.Cache.Min, config.DNS.Cache.Max)
		defer rc.Close()

		c = rc
	}

	h := handler.New(handler.Config{
		Allow:      allow,
		Block:      block,
		Upstreams:  config.DNS.Upstreams,
		Logger:     logger,
		Cache:      c,
		ClientFunc: handler.ClientFunc,
	})

	group, ctx := errgroup.WithContext(ctx)

	if config.Transport.UDP != nil {
		group.Go(func() error {
			return runDNSServer(ctx, logger, &dns.Server{
				Addr:    config.Transport.UDP.Bind,
				Net:     "udp",
				Handler: h,
			})
		})
	}

	if config.Transport.TCP != nil {
		group.Go(func() error {
			return runDNSServer(ctx, logger, &dns.Server{
				Addr:    config.Transport.TCP.Bind,
				Net:     "tcp",
				Handler: h,
			})
		})
	}

	if config.Transport.DOT != nil {
		group.Go(func() error {
			tlsConfig, err := loadTLSConfig(config.Transport.DOT.TLS.Cert, config.Transport.DOT.TLS.Key)
			if err != nil {
				return fmt.Errorf("failed to load tls config: %w", err)
			}

			return runDNSServer(ctx, logger, &dns.Server{
				Addr:      config.Transport.DOT.Bind,
				Net:       "tcp-tls",
				Handler:   h,
				TLSConfig: tlsConfig,
			})
		})
	}

	if config.Transport.DOH != nil {
		group.Go(func() error {
			var tlsConfig *tls.Config
			if config.Transport.DOH.TLS != nil && !config.Transport.DOH.DeferTLS {
				tlsConfig, err = loadTLSConfig(config.Transport.DOH.TLS.Cert, config.Transport.DOH.TLS.Key)
				if err != nil {
					return fmt.Errorf("failed to load tls config: %w", err)
				}
			}

			return runHTTPServer(ctx, logger, &http.Server{
				Addr:      config.Transport.DOH.Bind,
				Handler:   h,
				TLSConfig: tlsConfig,
			})
		})
	}

	if config.Metrics != nil {
		group.Go(func() error {
			return runHTTPServer(ctx, logger, &http.Server{
				Addr:    config.Metrics.Bind,
				Handler: promhttp.Handler(),
			})
		})
	}

	return group.Wait()
}

func runDNSServer(ctx context.Context, logger *slog.Logger, server *dns.Server) error {
	log := logger.With("net", server.Net, "addr", server.Addr)

	// Allow multiple listeners to use the same address/port if supported.
	server.ReusePort = true
	server.ReuseAddr = true

	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		log.Info("server starting")
		return server.ListenAndServe()
	})

	group.Go(func() error {
		<-ctx.Done()

		log.Warn("server shutting down")
		return server.Shutdown()
	})

	return group.Wait()
}

func runHTTPServer(ctx context.Context, logger *slog.Logger, server *http.Server) error {
	log := logger.With("addr", server.Addr, "net", "http")

	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		log.Info("server starting")

		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return err
	})

	group.Go(func() error {
		<-ctx.Done()

		log.Warn("server shutting down")
		return server.Shutdown(ctx)
	})

	return group.Wait()
}

func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}
