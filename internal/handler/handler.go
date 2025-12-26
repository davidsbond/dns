package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/davidsbond/x/set"
	"github.com/davidsbond/x/weightslice"
)

type (
	// The Handler type is a dns.Handler and http.Handler implementation that provides allow & block listing
	// functionality before sending DNS requests to an upstream DNS server.
	Handler struct {
		allow     *set.Set[string]
		block     *set.Set[string]
		upstreams *weightslice.Slice[string, time.Duration]
		logger    *slog.Logger
		udpClient *dns.Client
		tcpClient *dns.Client
	}
)

// New returns a new instance of the Handler type configured with the provided allow & block lists, desired
// upstream DNS servers and logger. This can be assigned to the Handler field of the dns.Server type.
func New(allow, block *set.Set[string], upstreams []string, logger *slog.Logger) *Handler {
	return &Handler{
		allow:  allow,
		block:  block,
		logger: logger,

		// We have a UDP client which we always use first, then a TCP client when we get truncated responses from
		// the upstream.
		udpClient: &dns.Client{Net: "udp", Timeout: time.Minute},
		tcpClient: &dns.Client{Net: "tcp", Timeout: time.Minute},

		// We want to weight the upstream DNS servers by their round-trip duration in ascending order, so the historically
		// fastest DNS upstream is always tried first.
		upstreams: weightslice.New[string, time.Duration](upstreams, weightslice.Ascending),
	}
}

// ServeDNS handles an inbound DNS request attempting to perform a DNS query using UDP or TCP.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	response := new(dns.Msg)
	response.SetReply(r)

	if len(r.Question) != 1 {
		// Handling multiple questions per request is typically not supported.
		h.dnsError(w, r, dns.RcodeNotImplemented)
		return
	}

	question := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(question.Name), ".")

	if h.block.Contains(name) && !h.allow.Contains(name) {
		h.dnsError(w, r, dns.RcodeNameError)
		return
	}

	resp, err := h.dnsUpstream(ctx, r)
	if err != nil {
		h.dnsError(w, r, dns.RcodeServerFailure)
		return
	}

	if err = w.WriteMsg(resp); err != nil {
		h.logger.With("error", err).Error("failed to write dns response")
	}
}

// ServeHTTP handles an inbound HTTP request attempting to perform a DNS query using DNS-over-HTTPs.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const maxBytes = 4096

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path != "/dns-query" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	req := new(dns.Msg)

	var (
		data []byte
		err  error
	)

	// DNS-over-HTTPs allows both POST and GET requests. If we're using a POST request we'll want to read directly
	// from the request body.
	if r.Method == http.MethodPost {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
			return
		}

		reader := http.MaxBytesReader(w, r.Body, maxBytes)
		defer reader.Close()

		data, err = io.ReadAll(reader)
		switch {
		case errors.Is(err, &http.MaxBytesError{}):
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		case err != nil:
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	// Otherwise, we look for the "dns" query parameter which contains the same thing the request body would have
	// but in a base64 encoded format.
	if r.Method == http.MethodGet {
		query := r.URL.Query().Get("dns")
		if query == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		data, err = base64.RawURLEncoding.DecodeString(query)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}

	if err = req.Unpack(data); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// From this point on, we're always responding with an HTTP 200 and the DNS-encoded messages, so we set the headers
	// now for all possible DNS responses.
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")

	if len(req.Question) != 1 {
		h.dnsError(w, req, dns.RcodeNotImplemented)
		return
	}

	question := req.Question[0]
	name := strings.TrimSuffix(strings.ToLower(question.Name), ".")

	if h.block.Contains(name) && !h.allow.Contains(name) {
		h.dnsError(w, req, dns.RcodeNameError)
		return
	}

	resp, err := h.dnsUpstream(r.Context(), req)
	if err != nil {
		h.dnsError(w, req, dns.RcodeServerFailure)
		return
	}

	wire, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack failure", http.StatusInternalServerError)
		return
	}

	if _, err = w.Write(wire); err != nil {
		h.logger.With("error", err).Error("failed to write http response")
	}
}

func (h *Handler) dnsError(w io.Writer, r *dns.Msg, code int) {
	response := new(dns.Msg)
	response.SetReply(r)
	response.SetRcode(r, code)

	data, err := response.Pack()
	if err != nil {
		// We panic here as we really should never be in this situation unless something has really gone wrong. There
		// shouldn't be a reason we can't pack the response that we're creating for errors. This would mean something
		// is wrong in the underlying dns module.
		panic(fmt.Errorf("failed to pack response: %w", err))
	}

	if _, err = w.Write(data); err != nil {
		h.logger.With("error", err, "question", r.Question[0].Name).Error("failed to respond to DNS request")
	}
}

func (h *Handler) dnsUpstream(ctx context.Context, r *dns.Msg) (*dns.Msg, error) {
	const udpSize = 1232

	// Before we upstream a DNS request, we'll cap the UDP size to prevent the upstream from sending large
	// or fragmented messages.
	opt := r.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
		}

		r.Extra = append(r.Extra, opt)
	}

	if opt.UDPSize() < udpSize {
		opt.SetUDPSize(udpSize)
	}

	// Iterate over the upstreams in ascending order of most recent round-trip-time.
	for i, upstream := range h.upstreams.Range() {
		logger := h.logger.With("upstream", upstream)

		resp, rtt, err := h.udpClient.ExchangeContext(ctx, r, upstream)
		if err != nil {
			logger.With("error", err).Error("failed to upstream DNS request")
			continue
		}

		// The upstream has given us a truncated response, so we need to switch over to TCP to get the full response.
		if resp.Truncated {
			resp, _, err = h.tcpClient.ExchangeContext(ctx, r, upstream)
			if err != nil {
				logger.With("error", err).Error("failed to upstream DNS request")
				continue
			}
		}

		// Update the weighting for this upstream based on its round-trip time. We always want to use the known
		// fastest upstream first. Since these are all initialized with a weight of zero we'll always pick ones
		// we've not used yet until all have been used at least once and a weighting has been set.
		h.upstreams.SetWeight(i, rtt)

		// If we got a successful response or that the domain name does not exist from the upstream, we forward that
		// back to the caller. Otherwise, we try the next upstream.
		switch resp.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			// Pass to the client for these codes.
		default:
			continue
		}

		// We want to avoid sending any EDNS0 options from the upstream to avoid leaking any upstream
		// metadata.
		opt = resp.IsEdns0()
		if opt != nil {
			opt.Option = nil
		}

		// We need to update the flags to correspond with what this DNS server provides, rather than the
		// upstream itself.
		resp.Authoritative = false
		resp.RecursionAvailable = true
		resp.AuthenticatedData = false

		return resp, nil
	}

	return nil, errors.New("failed querying all upstream DNS servers")
}
