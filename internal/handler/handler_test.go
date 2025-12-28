package handler_test

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/davidsbond/dns/internal/cache"
	"github.com/davidsbond/dns/internal/handler"
	"github.com/davidsbond/dns/internal/list"
	"github.com/davidsbond/x/set"
)

func TestHandler_ServeDNS(t *testing.T) {
	t.Parallel()

	errorCodes := []int{dns.RcodeNotImplemented, dns.RcodeServerFailure}

	allow, err := list.Allow(t.Context())
	require.NoError(t, err)

	block, err := list.Block(t.Context())
	require.NoError(t, err)

	tt := []struct {
		Name         string
		Request      func() *dns.Msg
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
			Request: func() *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:               uint16(rand.Intn(1 << 16)),
						RecursionDesired: true,
					},
					Question: []dns.Question{
						{
							Name:   "userlocation.googleapis.com.",
							Qtype:  dns.TypeA,
							Qclass: dns.ClassINET,
						},
					},
				}
			},
		},
		{
			Name:      "upstreams non-blocked domains",
			Allow:     allow,
			Block:     block,
			Upstreams: []string{"8.8.8.8:53", "8.8.4.4:53"},
			Request: func() *dns.Msg {
				return &dns.Msg{
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
			},
		},
		{
			Name:         "prevents blocked domains",
			Allow:        allow,
			Block:        block,
			Upstreams:    []string{"8.8.8.8:53", "8.8.4.4:53"},
			ExpectsError: true,
			ExpectedCode: dns.RcodeNameError,
			Request: func() *dns.Msg {
				return &dns.Msg{
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
			},
		},
		{
			Name:      "attempts multiple upstreams",
			Allow:     allow,
			Block:     block,
			Upstreams: []string{"0.0.0.0:1337", "8.8.4.4:53"},
			Request: func() *dns.Msg {
				return &dns.Msg{
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
			},
		},
		{
			Name:         "error when all upstreams fail",
			Allow:        allow,
			Block:        block,
			Upstreams:    []string{"0.0.0.0:1337"},
			ExpectsError: true,
			ExpectedCode: dns.RcodeServerFailure,
			Request: func() *dns.Msg {
				return &dns.Msg{
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
			},
		},
		{
			Name:         "rejects bad edns0 versions",
			Allow:        allow,
			Block:        block,
			ExpectsError: true,
			ExpectedCode: dns.RcodeBadVers,
			Request: func() *dns.Msg {
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

				msg.SetEdns0(1232, false)
				opt := msg.IsEdns0()
				opt.SetVersion(1)

				return msg
			},
		},
		{
			Name:         "rejects multiple questions",
			Allow:        allow,
			Block:        block,
			ExpectsError: true,
			ExpectedCode: dns.RcodeNotImplemented,
			Upstreams:    []string{"8.8.8.8:53", "8.8.4.4:53"},
			Request: func() *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:               uint16(rand.Intn(1 << 16)),
						RecursionDesired: true,
					},
					Question: []dns.Question{
						{
							Name:   "google.com.",
							Qtype:  dns.TypeA,
							Qclass: dns.ClassINET,
						},
						{
							Name:   "facebook.com.",
							Qtype:  dns.TypeA,
							Qclass: dns.ClassINET,
						},
					},
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			w := &MockDNSResponseWriter{}
			cfg := handler.Config{
				Allow:     tc.Allow,
				Block:     tc.Block,
				Upstreams: tc.Upstreams,
				Logger:    testLogger(t),
				Cache:     cache.NewNoopCache(),
			}

			handler.New(cfg).ServeDNS(w, tc.Request())

			if tc.ExpectsError {
				assert.EqualValues(t, tc.ExpectedCode, w.message.Rcode)
				return
			}

			require.NotContains(t, errorCodes, w.message.Rcode, "dns response should not contain an error")
			require.NotEmpty(t, w.message.Answer)
			assert.False(t, w.message.Authoritative)
			assert.True(t, w.message.RecursionAvailable)
			assert.False(t, w.message.AuthenticatedData)
		})
	}
}

func TestHandler_ServeHTTP(t *testing.T) {
	t.Parallel()

	errorCodes := []int{dns.RcodeNotImplemented, dns.RcodeServerFailure}

	allow, err := list.Allow(t.Context())
	require.NoError(t, err)

	block, err := list.Block(t.Context())
	require.NoError(t, err)

	tt := []struct {
		Name             string
		DNSRequest       func() *dns.Msg
		HTTPRequest      func(m *dns.Msg) *http.Request
		Upstreams        []string
		Allow            *set.Set[string]
		Block            *set.Set[string]
		ExpectsError     bool
		ExpectedHTTPCode int
		ExpectedDNSCode  int
	}{
		{
			Name:             "upstreams allowed domains",
			Allow:            allow,
			Block:            block,
			Upstreams:        []string{"8.8.8.8:53", "8.8.4.4:53"},
			ExpectedHTTPCode: http.StatusOK,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/dns-message")
				return r
			},
			DNSRequest: func() *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:               uint16(rand.Intn(1 << 16)),
						RecursionDesired: true,
					},
					Question: []dns.Question{
						{
							Name:   "userlocation.googleapis.com.",
							Qtype:  dns.TypeA,
							Qclass: dns.ClassINET,
						},
					},
				}
			},
		},
		{
			Name:             "upstreams non-blocked domains",
			Allow:            allow,
			Block:            block,
			Upstreams:        []string{"8.8.8.8:53", "8.8.4.4:53"},
			ExpectedHTTPCode: http.StatusOK,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/dns-message")
				return r
			},
			DNSRequest: func() *dns.Msg {
				return &dns.Msg{
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
			},
		},
		{
			Name:             "prevents blocked domains",
			Allow:            allow,
			Block:            block,
			Upstreams:        []string{"8.8.8.8:53", "8.8.4.4:53"},
			ExpectsError:     true,
			ExpectedDNSCode:  dns.RcodeNameError,
			ExpectedHTTPCode: http.StatusOK,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/dns-message")
				return r
			},
			DNSRequest: func() *dns.Msg {
				return &dns.Msg{
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
			},
		},
		{
			Name:             "attempts multiple upstreams",
			Allow:            allow,
			Block:            block,
			Upstreams:        []string{"0.0.0.0:1337", "8.8.4.4:53"},
			ExpectedHTTPCode: http.StatusOK,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/dns-message")
				return r
			},
			DNSRequest: func() *dns.Msg {
				return &dns.Msg{
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
			},
		},
		{
			Name:             "error when all upstreams fail",
			Allow:            allow,
			Block:            block,
			Upstreams:        []string{"0.0.0.0:1337"},
			ExpectsError:     true,
			ExpectedDNSCode:  dns.RcodeServerFailure,
			ExpectedHTTPCode: http.StatusOK,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/dns-message")
				return r
			},
			DNSRequest: func() *dns.Msg {
				return &dns.Msg{
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
			},
		},
		{
			Name:             "rejects bad edns0 versions",
			Allow:            allow,
			Block:            block,
			ExpectsError:     true,
			ExpectedDNSCode:  dns.RcodeBadVers,
			ExpectedHTTPCode: http.StatusOK,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/dns-message")
				return r
			},
			DNSRequest: func() *dns.Msg {
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

				msg.SetEdns0(1232, false)
				opt := msg.IsEdns0()
				opt.SetVersion(1)

				return msg
			},
		},
		{
			Name:             "rejects multiple questions",
			Allow:            allow,
			Block:            block,
			ExpectsError:     true,
			ExpectedDNSCode:  dns.RcodeNotImplemented,
			Upstreams:        []string{"8.8.8.8:53", "8.8.4.4:53"},
			ExpectedHTTPCode: http.StatusOK,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/dns-message")
				return r
			},
			DNSRequest: func() *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:               uint16(rand.Intn(1 << 16)),
						RecursionDesired: true,
					},
					Question: []dns.Question{
						{
							Name:   "google.com.",
							Qtype:  dns.TypeA,
							Qclass: dns.ClassINET,
						},
						{
							Name:   "facebook.com.",
							Qtype:  dns.TypeA,
							Qclass: dns.ClassINET,
						},
					},
				}
			},
		},
		{
			Name:             "rejects wrong http method",
			ExpectedHTTPCode: http.StatusMethodNotAllowed,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				r := httptest.NewRequest(http.MethodPut, "/dns-query", bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/dns-message")
				return r
			},
			DNSRequest: func() *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:               uint16(rand.Intn(1 << 16)),
						RecursionDesired: true,
					},
					Question: []dns.Question{
						{
							Name:   "google.com.",
							Qtype:  dns.TypeA,
							Qclass: dns.ClassINET,
						},
					},
				}
			},
		},
		{
			Name:             "rejects wrong http path",
			ExpectedHTTPCode: http.StatusNotFound,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				r := httptest.NewRequest(http.MethodPost, "/something", bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/dns-message")
				return r
			},
			DNSRequest: func() *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:               uint16(rand.Intn(1 << 16)),
						RecursionDesired: true,
					},
					Question: []dns.Question{
						{
							Name:   "google.com.",
							Qtype:  dns.TypeA,
							Qclass: dns.ClassINET,
						},
					},
				}
			},
		},
		{
			Name:             "rejects wrong content type",
			ExpectedHTTPCode: http.StatusUnsupportedMediaType,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/json")
				return r
			},
			DNSRequest: func() *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:               uint16(rand.Intn(1 << 16)),
						RecursionDesired: true,
					},
					Question: []dns.Question{
						{
							Name:   "google.com.",
							Qtype:  dns.TypeA,
							Qclass: dns.ClassINET,
						},
					},
				}
			},
		},
		{
			Name:             "upstreams via HTTP GET",
			Allow:            allow,
			Block:            block,
			Upstreams:        []string{"8.8.8.8:53", "8.8.4.4:53"},
			ExpectedHTTPCode: http.StatusOK,
			HTTPRequest: func(m *dns.Msg) *http.Request {
				data, err := m.Pack()
				require.NoError(t, err)

				return httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(data), nil)
			},
			DNSRequest: func() *dns.Msg {
				return &dns.Msg{
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
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := tc.HTTPRequest(tc.DNSRequest())
			cfg := handler.Config{
				Allow:     tc.Allow,
				Block:     tc.Block,
				Upstreams: tc.Upstreams,
				Logger:    testLogger(t),
				Cache:     cache.NewNoopCache(),
			}

			handler.New(cfg).ServeHTTP(w, r)

			require.EqualValues(t, tc.ExpectedHTTPCode, w.Code)

			if w.Code != http.StatusOK {
				return
			}

			assert.EqualValues(t, "application/dns-message", w.Header().Get("Content-Type"))
			assert.EqualValues(t, "no-store", w.Header().Get("Cache-Control"))

			response := new(dns.Msg)
			require.NoError(t, response.Unpack(w.Body.Bytes()))

			if tc.ExpectsError {
				assert.EqualValues(t, tc.ExpectedDNSCode, response.Rcode)
				return
			}

			require.NotContains(t, errorCodes, response.Rcode, "dns response should not contain an error")
			require.NotEmpty(t, response.Answer)
			assert.False(t, response.Authoritative)
			assert.True(t, response.RecursionAvailable)
			assert.False(t, response.AuthenticatedData)
		})
	}
}

func testLogger(t *testing.T) *slog.Logger {
	h := slog.NewTextHandler(t.Output(), &slog.HandlerOptions{
		AddSource: testing.Verbose(),
		Level:     slog.LevelDebug,
	})

	return slog.New(h).With("test", t.Name())
}
