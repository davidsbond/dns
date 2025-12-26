package api

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/davidsbond/x/set"
	"github.com/davidsbond/x/weightslice"
)

type (
	// The DNSAPI type is a dns.Handler implementation that provides allow & block listing functionality before sending
	// DNS requests to an upstream DNS server.
	DNSAPI struct {
		allow     *set.Set[string]
		block     *set.Set[string]
		upstreams *weightslice.Slice[string, time.Duration]
		logger    *slog.Logger
		client    *dns.Client
	}
)

// NewDNSAPI returns a new instance of the DNSAPI type configured with the provided allow & block lists, desired
// upstream DNS servers and logger. This can be assigned to the Handler field of the dns.Server type.
func NewDNSAPI(allow, block *set.Set[string], upstreams []string, logger *slog.Logger) *DNSAPI {
	return &DNSAPI{
		allow:  allow,
		block:  block,
		logger: logger,
		client: &dns.Client{Net: "udp"},
		// We want to weight the upstream DNS servers by their round-trip duration in ascending order, so the historically
		// fastest DNS upstream is always tried first.
		upstreams: weightslice.New[string, time.Duration](upstreams, weightslice.Ascending),
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
		// Handling multiple questions per request is typically not supported.
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

	for i, upstream := range api.upstreams.Range() {
		logger := api.logger.With(
			"upstream", upstream,
			"remote", w.RemoteAddr(),
			"question", question.Name,
		)

		resp, rtt, err := api.client.ExchangeContext(ctx, r, upstream)
		if err != nil {
			logger.With("error", err).Error("failed to upstream DNS request")
			continue
		}

		// Update the weighting for this upstream based on its round-trip time. We always want to use the known
		// fastest upstream first. Since these are all initialized with a weight of zero we'll always pick ones
		// we've not used yet until all have been used at least once and a weighting has been set.
		api.upstreams.SetWeight(i, rtt)

		// If we got a successful response or that the domain name does not exist from the upstream, we forward that
		// back to the caller. Otherwise, we try the next upstream.
		switch resp.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			// Pass to the client for these codes.
		default:
			continue
		}

		if err = w.WriteMsg(resp); err != nil {
			logger.With("error", err).Error("failed to respond to DNS request")
		}

		return
	}

	api.logger.With("remote", w.RemoteAddr(), "question", question.Name).Error("failed querying all upstream DNS servers")
	api.dnsError(w, r, dns.RcodeServerFailure)
}
