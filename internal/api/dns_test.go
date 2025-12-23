package api_test

import (
	"log/slog"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/davidsbond/dns/internal/api"
	"github.com/davidsbond/dns/internal/list"
	"github.com/davidsbond/x/set"
)

type (
	MockDNSResponseWriter struct {
		dns.ResponseWriter
		message *dns.Msg
	}
)

func (m *MockDNSResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.message = msg
	return nil
}

func (m *MockDNSResponseWriter) RemoteAddr() net.Addr {
	addr := &net.IPAddr{}

	return addr
}

func TestDNSAPI_ServeDNS(t *testing.T) {
	t.Parallel()

	errorCodes := []int{dns.RcodeNotImplemented, dns.RcodeServerFailure}

	allow, err := list.Allow(t.Context())
	require.NoError(t, err)

	block, err := list.Block(t.Context())
	require.NoError(t, err)

	tt := []struct {
		Name         string
		Request      *dns.Msg
		Upstreams    []string
		Allow        *set.Set[string]
		Block        *set.Set[string]
		ExpectsError bool
		ExpectedCode int
	}{
		{
			Name:      "upstreams allowed domains",
			Allow:     allow,
			Block:     block,
			Upstreams: []string{"8.8.8.8:53", "8.8.4.4:53"},
			Request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "userlocation.googleapis.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
		},
		{
			Name:      "upstreams non-blocked domains",
			Allow:     allow,
			Block:     block,
			Upstreams: []string{"8.8.8.8:53", "8.8.4.4:53"},
			Request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "dsb.dev.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
		},
		{
			Name:         "prevents blocked domains",
			Allow:        allow,
			Block:        block,
			Upstreams:    []string{"8.8.8.8:53", "8.8.4.4:53"},
			ExpectsError: true,
			ExpectedCode: dns.RcodeNameError,
			Request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "00280.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
		},
		{
			Name:      "attempts multiple upstreams",
			Allow:     allow,
			Block:     block,
			Upstreams: []string{"0.0.0.0:1337", "8.8.4.4:53"},
			Request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "dsb.dev.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
		},
		{
			Name:         "error when all upstreams fail",
			Allow:        allow,
			Block:        block,
			Upstreams:    []string{"0.0.0.0:1337"},
			ExpectsError: true,
			ExpectedCode: dns.RcodeServerFailure,
			Request: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "dsb.dev.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			w := &MockDNSResponseWriter{}

			api.NewDNSAPI(tc.Allow, tc.Block, tc.Upstreams, testLogger(t)).ServeDNS(w, tc.Request)

			if tc.ExpectsError {
				assert.EqualValues(t, tc.ExpectedCode, w.message.Rcode)
				return
			}

			require.NotContains(t, errorCodes, w.message.Rcode, "dns response should not contain an error")
			require.NotEmpty(t, w.message.Answer)
		})
	}
}

func testLogger(t *testing.T) *slog.Logger {
	handler := slog.NewTextHandler(t.Output(), &slog.HandlerOptions{
		AddSource: testing.Verbose(),
		Level:     slog.LevelDebug,
	})

	return slog.New(handler).With("test", t.Name())
}
