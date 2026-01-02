// Package cache provides  DNS-aware cache implementations for storing upstream DNS responses for a given TTL.
package cache

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/miekg/dns"
)

type (
	// The RistrettoCache type is a handler.Cache implementation that uses ristretto as its underlying storage.
	RistrettoCache struct {
		minTTL time.Duration
		maxTTL time.Duration

		store *ristretto.Cache[string, *dns.Msg]
	}
)

// NewRistrettoCache returns a new instance of the RistrettoCache type that will cache DNS queries using a ristretto
// cache. TTLs will be clamped to the minimum and maximum provided when the TTLs of upstream DNS queries exceed its
// boundary.
func NewRistrettoCache(minTTL, maxTTL time.Duration) *RistrettoCache {
	store, err := ristretto.NewCache(&ristretto.Config[string, *dns.Msg]{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	})
	if err != nil {
		// We aren't giving the user knobs to control things that could cause NewCache to error, so we're doing
		// something very wrong if we hit this branch.
		panic(err)
	}

	return &RistrettoCache{
		store:  store,
		minTTL: minTTL,
		maxTTL: maxTTL,
	}
}

// Close the cache.
func (c *RistrettoCache) Close() error {
	c.store.Close()
	return nil
}

// Put a request-response combination into the cache. RistrettoCache keys are deterministically created using the request
// and ignore fields that change across requests, such as the message id. If the response's code is not NOERROR or NXDOMAIN
// the response will not be cached.
func (c *RistrettoCache) Put(req, resp *dns.Msg) {
	key := createKey(req)

	var seconds uint32
	switch resp.Rcode {
	case dns.RcodeSuccess:
		if len(resp.Answer) > 0 {
			// RFC-2181 (5.2): For a populated response, we'll cache using the minimum TTL given in the answers.
			seconds = minimumTTL(resp.Answer)
			break
		}

		// RFC-2308 (5): Otherwise, we'll use the SOA TTL.
		seconds = negativeTTL(resp)
	case dns.RcodeNameError:
		seconds = negativeTTL(resp)
	default:
		// To avoid caching transient issues from an upstream, we'll skip caching any other response codes.
		return
	}

	if seconds == 0 {
		return
	}

	ttl := time.Duration(seconds) * time.Second

	if ttl < c.minTTL {
		ttl = c.minTTL
	}

	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}

	c.store.SetWithTTL(key, resp.Copy(), 0, ttl)

	// Wait for cache syncs if we're in tests. This is a little yucky but neater than having to shove sleeps
	// between every call to Put in tests.
	if testing.Testing() {
		c.store.Wait()
	}
}

// Get a DNS response from the cache based on the provided request. The returned response is ready to be returned to
// the client verbatim with updated TTLs based on the cache's expected expiry time.
func (c *RistrettoCache) Get(req *dns.Msg) (*dns.Msg, bool) {
	key := createKey(req)

	original, ok := c.store.Get(key)
	if !ok {
		cacheMisses.Inc()
		return nil, false
	}

	cached := original.Copy()

	// RFC-1035 (4.1.1): Map this copy of the cached response to the request.
	cached.Id = req.Id

	ttl, ok := c.store.GetTTL(key)
	if !ok {
		return nil, false
	}

	seconds := uint32(ttl.Seconds())
	if seconds == 0 {
		return nil, false
	}

	// RFC-{2181,2308}: Apply the remaining TTL in the cache to all sections of the response.
	for _, rr := range cached.Answer {
		rr.Header().Ttl = seconds
	}

	for _, rr := range cached.Ns {
		rr.Header().Ttl = seconds
	}

	for _, rr := range cached.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = seconds
		}
	}

	cacheHits.Inc()
	return cached, true
}

func createKey(req *dns.Msg) string {
	q := req.Question[0]

	// RFC-4035 (3.2.3): DNSSEC-aware caching MUST vary on DO bit
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
	}

	return fmt.Sprintf(
		"%s/%d/%d/%t",
		strings.ToLower(q.Name),
		q.Qtype,
		q.Qclass,
		do,
	)
}

func minimumTTL(rrs []dns.RR) uint32 {
	if len(rrs) == 0 {
		return 0
	}

	rr := slices.MinFunc(rrs, func(a, b dns.RR) int {
		return cmp.Compare(a.Header().Ttl, b.Header().Ttl)
	})

	return rr.Header().Ttl
}

func negativeTTL(msg *dns.Msg) uint32 {
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return min(soa.Minttl, soa.Hdr.Ttl)
		}
	}

	return 0
}
