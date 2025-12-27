// Package handler provides all handling logic for DNS queries over both standard (raw TCP and UDP) and encrypted
// (DNS-over-TLS, DNS-over-HTTPs) protocols. It includes the allow/block listing logic as well as upstream weighting
// by round-trip-time.
package handler

// Throughout this package are comments that link specific behavior to DNS-related RFCs. These RFCs can be read at:
// * RFC-1035 (Core DNS): 			https://www.rfc-editor.org/rfc/rfc1035.html
// * RFC-6891 (EDNS0): 				https://www.rfc-editor.org/rfc/rfc6891.html
// * RFC-4035 (DNSSEC signaling): 	https://www.rfc-editor.org/rfc/rfc4035.html
// * RFC-8484 (DNS over HTTPS):		https://www.rfc-editor.org/rfc/rfc8484.html
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

var (
	// We need to append this to the "Extra" section of the response whenever we have an EDNS0 version that we
	// do not support, so we declare it once here and pass it into Handler.dnsError when required.
	badVersionOpt = &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
)

func init() {
	// A little dirty, but we also need to specify the version and set our payload size once for this helpful
	// variable.
	badVersionOpt.SetVersion(0)
	badVersionOpt.SetUDPSize(udpPayloadSize)
}

const (
	udpPayloadSize = 1232
)

// ServeDNS handles an inbound DNS request attempting to perform a DNS query using UDP or TCP.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	response := new(dns.Msg)
	response.SetReply(r)

	// RFC-6891 (6.1.3): If a responder does not implement the requested EDNS version,it MUST respond with RCODE=BADVERS.
	if opt := r.IsEdns0(); opt != nil && opt.Version() != 0 {
		h.dnsError(w, r, dns.RcodeBadVers, badVersionOpt)
		return
	}

	// RFC-1035 (4.1.2): While the protocol allows multiple questions per message, most resolvers do not support this
	// and return NOTIMP.
	if len(r.Question) != 1 {
		h.dnsError(w, r, dns.RcodeNotImplemented)
		return
	}

	question := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(question.Name), ".")

	// RFC-1035 (4.3.1): NXDOMAIN indicates that the domain name does not exist. Used here for policy-based blocking.
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

	// RFC-8484 (4): DNS-over-HTTPS supports both GET and POST methods.
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
		// RFC-8484 (4.1): POST requests MUST use Content-Type: application/dns-message.
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

		// RFC-8484 (4.1): GET requests encode the DNS message using base64 in the "dns" query parameter.
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

	// RFC-8484 (5): DNS responses are always returned with HTTP 200.
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")

	// RFC-6891 (6.1.3): If a responder does not implement the requested EDNS version, it MUST respond with BADVERS.
	if opt := req.IsEdns0(); opt != nil && opt.Version() != 0 {
		h.dnsError(w, req, dns.RcodeBadVers, badVersionOpt)
		return
	}

	// RFC-1035 (4.1.2): While the protocol allows multiple questions per message, most resolvers do not support this
	// and return NOTIMP.
	if len(req.Question) != 1 {
		h.dnsError(w, req, dns.RcodeNotImplemented)
		return
	}

	question := req.Question[0]
	name := strings.TrimSuffix(strings.ToLower(question.Name), ".")

	// RFC-1035 (4.3.1): NXDOMAIN indicates that the domain name does not exist. Used here for  policy-based blocking.
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

func (h *Handler) dnsError(w io.Writer, r *dns.Msg, code int, extra ...dns.RR) {
	response := new(dns.Msg)
	response.SetReply(r)
	response.SetRcode(r, code)

	response.Extra = append(response.Extra, extra...)

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
	// RFC-6891 (6.2.3): EDNS allows clients to advertise a larger UDP payload size. We cap this to 1232 bytes to avoid
	// IP fragmentation.
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

	if opt.UDPSize() < udpPayloadSize {
		opt.SetUDPSize(udpPayloadSize)
	}

	// Iterate over the upstreams in ascending order of most recent round-trip-time.
	for i, upstream := range h.upstreams.Range() {
		logger := h.logger.With("upstream", upstream)

		resp, rtt, err := h.udpClient.ExchangeContext(ctx, r, upstream)
		if err != nil {
			logger.With("error", err).Error("failed to upstream DNS request")
			continue
		}

		// RFC-1035 (4.2.2): If the TC (truncated) bit is set, the client should retry using TCP.
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

		// RFC-6891 (6.1.1): EDNS0 options are hop-by-hop and MUST NOT be blindly forwarded. We strip upstream options
		// to avoid leaking upstream metadata.
		opt = resp.IsEdns0()
		if opt != nil {
			opt.Option = nil
		}

		// RFC-{1035,4035}: This server is not authoritative but does provide recursion.
		resp.Authoritative = false
		resp.RecursionAvailable = true

		// RFC-4035 (3.2.3): The AD (Authenticated Data) bit MUST only be set by a resolver that has performed DNSSEC
		// validation itself.
		resp.AuthenticatedData = false

		return resp, nil
	}

	return nil, errors.New("failed querying all upstream DNS servers")
}
