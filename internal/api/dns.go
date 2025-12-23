package api

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/davidsbond/x/set"
)

type (
	// The DNSAPI type is a dns.Handler implementation that provides allow & block listing functionality before sending
	// DNS requests to an upstream DNS server.
	DNSAPI struct {
		allow     *set.Set[string]
		block     *set.Set[string]
		upstreams []string
		logger    *slog.Logger
		client    *dns.Client
	}
)

// NewDNSAPI returns a new instance of the DNSAPI type configured with the provided allow & block lists, desired
// upstream DNS servers and logger. This can be assigned to the Handler field of the dns.Server type.
func NewDNSAPI(allow, block *set.Set[string], upstreams []string, logger *slog.Logger) *DNSAPI {
	return &DNSAPI{
		allow:     allow,
		block:     block,
		upstreams: upstreams,
		logger:    logger,
		client:    &dns.Client{Net: "udp4"},
	}
}

// ServeDNS handles an inbound DNS request. If the request matches a domain on the allow list, or does not appear in
// the block list, it is sent upstream to the specified DNS upstreams. Each upstream will be attempted in order of
// appearance and iteration will only occur on failure of a specific upstream to resolve the DNS request.
func (api *DNSAPI) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	response := new(dns.Msg)
	response.SetReply(r)

	if len(r.Question) != 1 {
		api.dnsError(w, r, dns.RcodeNotImplemented)
		return
	}

	question := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(question.Name), ".")

	if api.allow.Contains(name) {
		api.dnsUpstream(ctx, w, r.Id, question)
		return
	}

	if api.block.Contains(name) {
		api.dnsError(w, r, dns.RcodeNameError)
		return
	}

	api.dnsUpstream(ctx, w, r.Id, question)
}

func (api *DNSAPI) dnsError(w dns.ResponseWriter, r *dns.Msg, code int) {
	response := new(dns.Msg)
	response.SetReply(r)
	response.SetRcode(r, code)

	if err := w.WriteMsg(response); err != nil {
		api.logger.
			With(
				"error", err,
				"remote", w.RemoteAddr(),
				"question", r.Question[0].Name,
			).
			Error("failed to respond to DNS request")
	}
}

func (api *DNSAPI) dnsUpstream(ctx context.Context, w dns.ResponseWriter, id uint16, question dns.Question) {
	r := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               id,
			RecursionDesired: true,
		},
		Question: []dns.Question{question},
	}

	for _, upstream := range api.upstreams {
		resp, _, err := api.client.ExchangeContext(ctx, r, upstream)
		if err != nil {
			api.logger.
				With(
					"error", err,
					"upstream", upstream,
					"remote", w.RemoteAddr(),
					"question", r.Question[0].Name,
				).
				Error("failed to upstream DNS request")

			api.dnsError(w, r, dns.RcodeServerFailure)
			continue
		}

		if resp.MsgHdr.Rcode != dns.RcodeSuccess {
			continue
		}

		if err = w.WriteMsg(resp); err != nil {
			api.logger.
				With(
					"error", err,
					"remote", w.RemoteAddr(),
					"question", r.Question[0].Name,
				).
				Error("failed to respond to DNS request")
		}

		return
	}

	api.logger.
		With(
			"remote", w.RemoteAddr(),
			"question", r.Question[0].Name,
		).
		Error("failed querying all upstream DNS servers")

	api.dnsError(w, r, dns.RcodeNameError)
}
