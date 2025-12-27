package server_test

import (
	"context"
	"math/rand"
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

	ca, caKey := createCA(t)
	certFile, keyFile := createServerTLS(t, ca, caKey)
	clientTLS := createTLSConfig(t, ca)

	config := server.Config{
		DNS: server.DNSConfig{
			Upstreams: []string{"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53"},
		},
		Transport: server.TransportConfig{
			UDP: &server.UDPConfig{
				Bind: "127.0.0.1:4000",
			},
			TCP: &server.TCPConfig{
				Bind: "127.0.0.1:4000",
			},
			DOT: &server.DOTConfig{
				Bind: "127.0.0.1:4001",
			},
			TLS: &server.TLSConfig{
				Cert: certFile,
				Key:  keyFile,
			},
		},
	}

	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		t.Log("starting test server")
		require.NoError(t, server.Run(ctx, config))

		return nil
	})

	// Wait for the server to start up.
	<-time.After(time.Second)

	t.Run("raw protocols", func(t *testing.T) {
		clients := map[string]*dns.Client{
			config.Transport.UDP.Bind: {
				Net: "udp",
			},
			config.Transport.TCP.Bind: {
				Net: "tcp",
			},
			config.Transport.DOT.Bind: {
				Net:       "tcp-tls",
				TLSConfig: clientTLS,
			},
		}

		t.Run("handles domain in block list", func(t *testing.T) {
			msg := &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               uint16(rand.Intn(1 << 16)),
					RecursionDesired: true,
				},
				Question: []dns.Question{
					{
						Name:   "00280.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			}

			for addr, client := range clients {
				resp, _, err := client.ExchangeContext(ctx, msg, addr)
				require.NoError(t, err)
				assert.EqualValues(t, dns.RcodeNameError, resp.Rcode)
				assert.Empty(t, resp.Answer)
			}
		})

		t.Run("handles domain in allow list", func(t *testing.T) {
			msg := &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               uint16(rand.Intn(1 << 16)),
					RecursionDesired: true,
				},
				Question: []dns.Question{
					{
						Name:   "www.googletagmanager.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			}

			for addr, client := range clients {
				resp, _, err := client.ExchangeContext(ctx, msg, addr)
				require.NoError(t, err)
				assert.EqualValues(t, dns.RcodeSuccess, resp.Rcode)
				assert.NotEmpty(t, resp.Answer)
			}
		})

		t.Run("handles domain not in either list", func(t *testing.T) {
			msg := &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               uint16(rand.Intn(1 << 16)),
					RecursionDesired: true,
				},
				Question: []dns.Question{
					{
						Name:   "dsb.dev.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			}

			for addr, client := range clients {
				resp, _, err := client.ExchangeContext(ctx, msg, addr)
				require.NoError(t, err)
				assert.EqualValues(t, dns.RcodeSuccess, resp.Rcode)
				assert.NotEmpty(t, resp.Answer)
			}
		})
	})

	// Shutdown the server and give it some time to gracefully exit.
	cancel()
	<-time.After(time.Second)
}
