package cache

import (
	"github.com/miekg/dns"
)

type (
	// The NoopCache type is a handler.Cache implementation that does nothing. It should be used when disabling
	// caching entirely.
	NoopCache struct{}
)

// NewNoopCache returns a new instance of the NoopCache type.
func NewNoopCache() *NoopCache {
	return &NoopCache{}
}

// Put does nothing.
func (c *NoopCache) Put(_, _ *dns.Msg) {}

// Get does nothing, returning nil, false.
func (c *NoopCache) Get(_ *dns.Msg) (*dns.Msg, bool) {
	return nil, false
}
