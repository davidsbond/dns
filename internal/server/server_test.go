package server_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/davidsbond/dns/internal/server"
)

func TestRun(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip()
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		t.Log("starting test server")
		require.NoError(t, server.Run(ctx, server.Config{
			Addr:      "127.0.0.1:4000",
			Upstreams: []string{"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53"},
			Logger: slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{
				AddSource: testing.Verbose(),
				Level:     slog.LevelDebug,
			})),
		}))

		return nil
	})

	client := &dns.Client{
		Net: "udp4",
	}

	// Wait for the server to start up.
	<-time.After(time.Second)

	t.Run("handles domain in block list", func(t *testing.T) {
		msg := &dns.Msg{
			Question: []dns.Question{
				{
					Name:   "00280.com.",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				},
			},
		}

		resp, _, err := client.ExchangeContext(ctx, msg, "127.0.0.1:4000")
		require.NoError(t, err)
		assert.EqualValues(t, dns.RcodeNameError, resp.Rcode)
		assert.Empty(t, resp.Answer)
	})

	t.Run("handles domain in allow list", func(t *testing.T) {
		msg := &dns.Msg{
			Question: []dns.Question{
				{
					Name:   "www.googletagmanager.com.",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				},
			},
		}

		resp, _, err := client.ExchangeContext(ctx, msg, "127.0.0.1:4000")
		require.NoError(t, err)
		assert.EqualValues(t, dns.RcodeSuccess, resp.Rcode)
		assert.NotEmpty(t, resp.Answer)
	})

	t.Run("handles domain not in either list", func(t *testing.T) {
		msg := &dns.Msg{
			Question: []dns.Question{
				{
					Name:   "dsb.dev.",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				},
			},
		}

		resp, _, err := client.ExchangeContext(ctx, msg, "127.0.0.1:4000")
		require.NoError(t, err)
		assert.EqualValues(t, dns.RcodeSuccess, resp.Rcode)
		assert.NotEmpty(t, resp.Answer)
	})

	// Shutdown the server and give it some time to gracefully exit.
	cancel()
	<-time.After(time.Second)
}
