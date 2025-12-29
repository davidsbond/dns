package server_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/davidsbond/dns/internal/server"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tt := []struct {
		Name         string
		File         string
		Expected     server.Config
		ExpectsError bool
	}{
		{
			Name: "full & valid",
			File: "full.toml",
			Expected: server.Config{
				DNS: server.DNSConfig{
					Upstreams: []string{"1.1.1.1:53", "1.0.0.1:53"},
					Cache: &server.CacheConfig{
						Min: time.Minute,
						Max: time.Hour,
					},
				},
				Transport: server.TransportConfig{
					UDP: &server.UDPConfig{Bind: "127.0.0.1:53"},
					TCP: &server.TCPConfig{Bind: "127.0.0.1:53"},
					DOT: &server.DOTConfig{
						Bind: "127.0.0.1:853",
						TLS: &server.TLSConfig{
							Cert: "path/to/cert.pem",
							Key:  "path/to/key.pem",
						},
					},
					DOH: &server.DOHConfig{
						Bind: "127.0.0.1:443",
						TLS: &server.TLSConfig{
							Cert: "path/to/cert.pem",
							Key:  "path/to/key.pem",
						},
					},
				},
			},
		},
		{
			Name:         "invalid",
			File:         "invalid.toml",
			ExpectsError: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			path := filepath.Join("testdata", tc.File)

			actual, err := server.LoadConfig(path)
			if tc.ExpectsError {
				assert.Zero(t, actual)
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.EqualValues(t, tc.Expected, actual)
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tt := []struct {
		Name         string
		File         string
		ExpectsError bool
	}{
		{
			Name:         "no listeners",
			File:         "no_listeners.toml",
			ExpectsError: true,
		},
		{
			Name:         "no upstreams",
			File:         "no_upstreams.toml",
			ExpectsError: true,
		},
		{
			Name:         "no tls with dot/doh",
			File:         "no_tls.toml",
			ExpectsError: true,
		},
		{
			Name:         "invalid cache ttls",
			File:         "bad_cache.toml",
			ExpectsError: true,
		},
		{
			Name:         "dns-over-https without defer and no tls",
			File:         "bad_doh.toml",
			ExpectsError: true,
		},
		{
			Name:         "valid config",
			File:         "full.toml",
			ExpectsError: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			path := filepath.Join("testdata", tc.File)
			config, err := server.LoadConfig(path)
			require.NoError(t, err)

			err = config.Validate()
			if tc.ExpectsError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
