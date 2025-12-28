package cache_test

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/davidsbond/dns/internal/cache"
)

func TestRistrettoCache(t *testing.T) {
	t.Parallel()

	tt := []struct {
		Name        string
		MinTTL      time.Duration
		MaxTTL      time.Duration
		Request     func() *dns.Msg
		Response    func(req *dns.Msg) *dns.Msg
		ExpectCache bool
		Expected    func(req *dns.Msg) *dns.Msg
	}{
		{
			Name:        "basic NOERROR",
			MinTTL:      time.Minute,
			MaxTTL:      time.Hour,
			ExpectCache: true,
			Request: func() *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:     1,
						Opcode: dns.OpcodeQuery,
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
			Response: func(req *dns.Msg) *dns.Msg {
				res := new(dns.Msg)
				res.SetReply(req)

				res.Rcode = dns.RcodeSuccess
				res.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Ttl: 120,
						},
						A: net.ParseIP("127.0.0.1"),
					},
				}

				return res
			},
			Expected: func(req *dns.Msg) *dns.Msg {
				res := new(dns.Msg)
				res.SetReply(req)

				res.Rcode = dns.RcodeSuccess
				res.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Ttl: 120,
						},
						A: net.ParseIP("127.0.0.1"),
					},
				}

				return res
			},
		},
		{
			Name:        "basic NXDOMAIN",
			MinTTL:      time.Minute,
			MaxTTL:      time.Hour,
			ExpectCache: true,
			Request: func() *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:     1,
						Opcode: dns.OpcodeQuery,
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
			Response: func(req *dns.Msg) *dns.Msg {
				res := new(dns.Msg)
				res.SetReply(req)

				res.Rcode = dns.RcodeNameError
				res.Ns = []dns.RR{
					&dns.SOA{
						Hdr: dns.RR_Header{
							Ttl: 120,
						},
						Minttl: 120,
					},
				}

				return res
			},
			Expected: func(req *dns.Msg) *dns.Msg {
				res := new(dns.Msg)
				res.SetReply(req)

				res.Rcode = dns.RcodeNameError
				res.Ns = []dns.RR{
					&dns.SOA{
						Hdr: dns.RR_Header{
							Ttl: 120,
						},
						Minttl: 120,
					},
				}

				return res
			},
		},
		{
			Name:        "no TTL, no cache",
			MinTTL:      time.Minute,
			MaxTTL:      time.Hour,
			ExpectCache: false,
			Request: func() *dns.Msg {
				return &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:     1,
						Opcode: dns.OpcodeQuery,
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
			Response: func(req *dns.Msg) *dns.Msg {
				res := new(dns.Msg)
				res.SetReply(req)

				res.Rcode = dns.RcodeSuccess
				res.Answer = []dns.RR{
					&dns.A{
						A: net.ParseIP("127.0.0.1"),
					},
				}

				return res
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			c := cache.NewRistrettoCache(tc.MinTTL, tc.MaxTTL)

			req := tc.Request()
			res := tc.Response(req)

			c.Put(req, res)

			actual, ok := c.Get(tc.Request())
			if !tc.ExpectCache {
				require.False(t, ok)
				require.Nil(t, actual)
				return
			}

			expected := tc.Expected(req)
			assert.EqualValues(t, expected.Rcode, actual.Rcode)
			for i := range expected.Answer {
				assert.LessOrEqual(t, time.Duration(actual.Answer[i].Header().Ttl)*time.Second, tc.MaxTTL)
			}
		})
	}
}
