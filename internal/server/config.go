package server

import (
	"errors"
	"time"

	"github.com/BurntSushi/toml"
)

type (
	// The Config type contains fields used to configure the DNS server.
	Config struct {
		// DNS specific configuration values.
		DNS DNSConfig `toml:"dns"`
		// Individual transports used by the DNS server.
		Transport TransportConfig `toml:"transport"`
	}

	// The DNSConfig type contains fields for configuring specific DNS behavior.
	DNSConfig struct {
		// The upstream DNS servers to use for allowed DNS queries.
		Upstreams []string `toml:"upstreams"`
		// Configuration for DNS request caching.
		Cache *CacheConfig `toml:"cache"`
	}

	// The CacheConfig type contains fields used to configure DNS request caching.
	CacheConfig struct {
		// The minimum TTL for caching DNS responses from upstream. This is used to clamp TTLs to a minimum value
		// should the TTL from the upstream be below it.
		Min time.Duration `toml:"min"`
		// The maximum TTL for caching DNS responses from upstream. This is used to clamp TTLs to a maximum value
		// should the TTL from the upstream be above it.
		Max time.Duration `toml:"max"`
	}

	// The TransportConfig type contains fields used to configure the various transport methods supported by the
	// DNS server.
	TransportConfig struct {
		// Enables DNS over UDP.
		UDP *UDPConfig `toml:"udp"`
		// Enables DNS over TCP.
		TCP *TCPConfig `toml:"tcp"`
		// Enables DNS-over-TLS. When not nil, the TLS field must be populated.
		DOT *DOTConfig `toml:"dot"`
		// Enables DNS-over-HTTPs. When not nil, the TLS field must be populated.
		DOH *DOHConfig `toml:"doh"`
		// Contains fields for configuring TLS. Must be set when using DNS-over-TLS or DNS-over-HTTPs.
		TLS *TLSConfig `toml:"tls"`
	}

	// The UDPConfig type contains fields for configuring the UDP listener.
	UDPConfig struct {
		// The bind address of the UDP listener.
		Bind string `toml:"bind"`
	}

	// The TCPConfig type contains fields for configuring the TCP listener.
	TCPConfig struct {
		// The bind address of the TCP listener.
		Bind string `toml:"bind"`
	}

	// The DOTConfig type contains fields for configuring the DNS-over-TLS listener.
	DOTConfig struct {
		// The bind address of the DNS-over-TLS listener.
		Bind string `toml:"bind"`
	}

	// The DOHConfig type contains fields for configuring the DNS-over-HTTPs listener.
	DOHConfig struct {
		// The bind address of the DNS-over-HTTPs listener.
		Bind string `toml:"bind"`
		// Whether to defer TLS termination to a reverse proxy in front of the server. Effectively converts
		// DNS-over-HTTPs to DNS-over-HTTP instead.
		DeferTLS bool `toml:"defer-tls"`
	}

	// The TLSConfig type contains fields for configuring TLS for DNS-over-TLS or DNS-over-HTTPs.
	TLSConfig struct {
		// The path to the certificate file.
		Cert string `toml:"cert"`
		// The path to the key file.
		Key string `toml:"key"`
	}
)

// DefaultConfig returns a Config type containing default working values for the DNS server. By default, it will
// upstream to Cloudflare using raw UDP and TCP on port 53.
func DefaultConfig() Config {
	return Config{
		DNS: DNSConfig{
			Upstreams: []string{"8.8.8.8:53", "8.8.4.4:53"},
			Cache: &CacheConfig{
				Min: time.Minute,
				Max: time.Hour,
			},
		},
		Transport: TransportConfig{
			UDP: &UDPConfig{
				Bind: "0.0.0.0:53",
			},
			TCP: &TCPConfig{
				Bind: "0.0.0.0:53",
			},
		},
	}
}

// LoadConfig the configuration file at the specified path. The configuration file is expected in TOML format.
func LoadConfig(path string) (Config, error) {
	var config Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return Config{}, err
	}

	return config, nil
}

// Validate the configuration fields.
func (c *Config) Validate() error {
	return errors.Join(
		c.DNS.validate(),
		c.Transport.validate(),
	)
}

func (c *DNSConfig) validate() error {
	if len(c.Upstreams) == 0 {
		return errors.New("no dns upstreams specified")
	}

	if c.Cache == nil {
		return nil
	}

	if c.Cache.Max < c.Cache.Min || c.Cache.Min > c.Cache.Max {
		return errors.New("cache's max TTL must be greater than the min TTL")
	}

	return nil
}

func (t *TransportConfig) validate() error {
	// We never want a server that does nothing at all.
	if t.UDP == nil && t.TCP == nil && t.DOT == nil && t.DOH == nil {
		return errors.New("at least one transport must be specified")
	}

	// If we're enabling DNS-over-HTTPs and not deferring the TLS termination to a reverse proxy, we must have the
	// "tls" section of the configuration available.
	if (t.DOH != nil && !t.DOH.DeferTLS) && t.TLS == nil {
		return errors.New("tls cert & key must be specified when using dns over HTTPs without deferral")
	}

	// For DNS-over-TLS, there's not much point in adding a defer flag, since the caller can just do this themselves
	// with a reverse proxy and go straight to the regular TCP endpoint.
	if t.DOT != nil && t.TLS == nil {
		return errors.New("tls cert & key must be specified when using dns over TLS")
	}

	if t.UDP != nil && t.UDP.Bind == "" {
		return errors.New("udp bind address must be specified when using dns over UDP")
	}

	if t.TCP != nil && t.TCP.Bind == "" {
		return errors.New("tcp bind address must be specified when using dns over TCP")
	}

	if t.DOH != nil && t.DOH.Bind == "" {
		return errors.New("doh bind address must be specified when using dns over HTTPs")
	}

	if t.DOT != nil && t.DOT.Bind == "" {
		return errors.New("dot bind address must be specified when using dns over TLS")
	}

	if t.TLS != nil && (t.TLS.Cert == "" || t.TLS.Key == "") {
		return errors.New("tls cert and key must be specified when using tls")
	}

	return nil
}
