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
	"slices"
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
		udpClient DNSClient
		tcpClient DNSClient
		cache     Cache
	}

	// The Config type contains fields used to configure the Handler.
	Config struct {
		// The list of allowed domains.
		Allow *set.Set[string]
		// The list of blocked domains.
		Block *set.Set[string]
		// Upstream DNS servers to forward unblocked/allowed DNS queries to.
		Upstreams []string
		// The logger to use for errors.
		Logger *slog.Logger
		// The cache to use for reducing upstream DNS calls.
		Cache Cache
		// Function  used to create DNS clients for upstreaming requests. This is typically used to swap out upstream calls
		// with mock clients in tests. For normal usage, use ClientFunc.
		ClientFunc func(net string, timeout time.Duration) DNSClient
	}

	// The Cache interface describes types that can cache pairs of DNS requests and responses. Cache implementations
	// should be DNS aware, handling flags & TTLs appropriately.
	Cache interface {
		// Put should place a request-response combination into the cache.
		Put(req, resp *dns.Msg)
		// Get should obtain a response from the cache based on the given request. The second return value indicates
		// presence in the cache.
		Get(req *dns.Msg) (*dns.Msg, bool)
	}

	// The DNSClient interface describes types that can perform DNS query exchanges.
	DNSClient interface {
		// ExchangeContext should perform  DNS exchange for the given dns.Msg and address, returning the response
		// round-trip time and any errors.
		ExchangeContext(ctx context.Context, r *dns.Msg, addr string) (*dns.Msg, time.Duration, error)
	}
)

// ClientFunc returns a DNSClient implementation using the dns.Client type.
func ClientFunc(net string, timeout time.Duration) DNSClient {
	return &dns.Client{Net: net, Timeout: timeout}
}

// New returns a new instance of the Handler type based on the given configuration. This can be assigned to the Handler
// field of the dns.Server and http.Server types.
func New(config Config) *Handler {
	return &Handler{
		allow:  config.Allow,
		block:  config.Block,
		logger: config.Logger,

		// We have a UDP client which we always use first, then a TCP client when we get truncated responses from
		// the upstream.
		udpClient: config.ClientFunc("udp", time.Minute),
		tcpClient: config.ClientFunc("tcp", time.Minute),

		// We want to weight the upstream DNS servers by their round-trip duration in ascending order, so the historically
		// fastest DNS upstream is always tried first.
		upstreams: weightslice.New[string, time.Duration](config.Upstreams, weightslice.Ascending),

		// We use an in-memory cache for reducing the number of upstream calls as DNS can be a very noisy protocol for
		// regular use.
		cache: config.Cache,
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

	if !h.validateMsg(w, r) {
		return
	}

	if !h.checkLists(w, r) {
		return
	}

	resp, err := h.upstream(ctx, r)
	if err != nil {
		h.dnsError(w, r, dns.RcodeServerFailure)
		return
	}

	if err = w.WriteMsg(resp); err != nil {
		h.logger.With("error", err).Error("failed to write dns response")
	}

	dnsResponses.WithLabelValues(dns.RcodeToString[resp.Rcode]).Inc()
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

		var mbe *http.MaxBytesError
		data, err = io.ReadAll(reader)
		switch {
		case errors.As(err, &mbe):
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

	if !h.validateMsg(w, req) {
		return
	}

	if !h.checkLists(w, req) {
		return
	}

	resp, err := h.upstream(r.Context(), req)
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

	dnsResponses.WithLabelValues(dns.RcodeToString[resp.Rcode]).Inc()
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

	dnsResponses.WithLabelValues(dns.RcodeToString[response.Rcode]).Inc()
}

func (h *Handler) upstream(ctx context.Context, r *dns.Msg) (*dns.Msg, error) {
	// Skip the upstreams if we have this response in the cache already.
	if resp, ok := h.cache.Get(r); ok {
		return resp, nil
	}

	// Iterate over the upstreams in ascending order of most recent round-trip-time.
	for i, upstream := range h.upstreams.Range() {
		// For safety, we'll use a copy of the request in case calls to ExchangeContext perform any mutations on the
		// request that we don't want to propagate to other upstreams, likely not necessary but defensive.
		request := r.Copy()

		// RFC-6891 (6.2.3): EDNS allows clients to advertise a larger UDP payload size. We cap this to 1232 bytes to avoid
		// IP fragmentation.
		opt := request.IsEdns0()
		if opt == nil {
			opt = &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeOPT,
				},
			}

			request.Extra = append(request.Extra, opt)
		}

		if opt.UDPSize() < udpPayloadSize {
			opt.SetUDPSize(udpPayloadSize)
		}

		logger := h.logger.With("upstream", upstream, "name", request.Question[0].Name)

		resp, rtt, err := h.udpClient.ExchangeContext(ctx, request, upstream)
		if err != nil {
			logger.With("error", err).Error("failed to upstream DNS request")
			continue
		}

		dnsUpstreamed.WithLabelValues(upstream).Inc()

		// RFC-1035 (4.2.2): If the TC (truncated) bit is set, the client should retry using TCP.
		if resp.Truncated {
			resp, _, err = h.tcpClient.ExchangeContext(ctx, request, upstream)
			if err != nil {
				logger.With("error", err).Error("failed to upstream DNS request")
				continue
			}

			// If the TCP response has also been truncated, we'll act as if we got a SERVFAIL response.
			if resp.Truncated {
				logger.Error("got truncated response using fallback TCP exchange")
				continue
			}
		}

		// If we got a successful response or that the domain name does not exist from the upstream, we forward that
		// back to the caller. Otherwise, we try the next upstream.
		switch resp.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			// Update the weighting for this upstream based on its round-trip time. We always want to use the known
			// fastest upstream first. Since these are all initialized with a weight of zero we'll always pick ones
			// we've not used yet until all have been used at least once and a weighting has been set.
			//
			// Here we use the round-trip time of the original UDP exchange. We do not take the TCP round-trip time
			// into account. We also only care about the timing when we have NOERROR or NXDOMAIN.
			h.upstreams.SetWeight(i, rtt)
			dnsUpstreamSeconds.WithLabelValues(upstream).Observe(rtt.Seconds())
		default:
			continue
		}

		// RFC-6891 (6.1.1): EDNS0 options are hop-by-hop and MUST NOT be blindly forwarded. We strip upstream options
		// to avoid leaking upstream metadata.
		if opt = resp.IsEdns0(); opt != nil {
			resp.Extra = slices.DeleteFunc(resp.Extra, func(rr dns.RR) bool {
				_, ok := rr.(*dns.OPT)
				return ok
			})
		}

		// RFC-{1035,4035}: This server is not authoritative but does provide recursion.
		resp.Authoritative = false
		resp.RecursionAvailable = true

		// RFC-4035 (3.2.3): The AD (Authenticated Data) bit MUST only be set by a resolver that has performed DNSSEC
		// validation itself.
		resp.AuthenticatedData = false

		// At this point, we can cache the request/response combination for faster subsequent queries of this domain.
		h.cache.Put(r, resp)

		return resp, nil
	}

	return nil, errors.New("failed querying all upstream DNS servers")
}

func (h *Handler) validateMsg(w io.Writer, r *dns.Msg) bool {
	// RFC-6891 (6.1.3): If a responder does not implement the requested EDNS version,it MUST respond with RCODE=BADVERS.
	if opt := r.IsEdns0(); opt != nil && opt.Version() != 0 {
		h.dnsError(w, r, dns.RcodeBadVers, badVersionOpt)

		return false
	}

	// RFC-1035 (4.1.2): While the protocol allows multiple questions per message, most resolvers do not support this
	// and return NOTIMP.
	if len(r.Question) != 1 {
		h.dnsError(w, r, dns.RcodeNotImplemented)

		return false
	}

	return true
}

func (h *Handler) checkLists(w io.Writer, r *dns.Msg) bool {
	question := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(question.Name), ".")

	dnsQueries.WithLabelValues(dns.TypeToString[question.Qtype]).Inc()

	// RFC-1035 (4.3.1): NXDOMAIN indicates that the domain name does not exist. Used here for  policy-based blocking.
	if h.block.Contains(name) && !h.allow.Contains(name) {
		dnsBlocked.Inc()
		h.dnsError(w, r, dns.RcodeNameError)
		return false
	}

	return true
}
