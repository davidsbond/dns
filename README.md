# dns

This project is a small, standards-compliant DNS forwarding server written in Go. It implements policy-based allow and
block listing using curated, built-in domain lists that are versioned and shipped with the binary, forwards queries to
multiple upstream resolvers with latency-aware selection, and supports both traditional DNS transports (UDP and TCP) as
well as encrypted protocols including DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH).

## Installation

The DNS server is available as a binary for Windows, Mac & Linux as well as a Docker image. Binaries can be obtained
from the [releases page](https://github.com/davidsbond/dns/releases) while Docker images can be pulled
from [ghcr.io](https://github.com/davidsbond/dns/pkgs/container/dns).

### Usage

The server is operated via a single `serve` command, which accepts an optional configuration file. Run `dns --help` for
detailed usage information.

### Configuration

By default, the server will run on UDP & TCP ports 53 and serve regular, unencrypted DNS queries that upstream to
Cloudflare's DNS servers (1.1.1.1, 1.0.0.1). To modify this behavior, you must specify a TOML configuration file and
pass its path as the first argument to `dns serve`. Below is a description of the configuration file format:

> [!NOTE]
> Allow and block lists are not configurable via the configuration file. They are embedded in the binary and updated
> through new releases.

```toml
[dns]
# Upstreams to use for allowed DNS queries including port numbers (required).
upstreams = ["1.1.1.1:53", "1.0.0.1:53"]

# Optional DNS caching configuration. TTLs are derived from upstream responses (including negative caching TTLs) and 
# then clamped to this range.
[dns.cache]
min = "1m"
max = "1h"

# Each [transport.*] section is optional but at least one must be specified.

[transport.udp]
# Bind address for UDP based transport. 
bind = "127.0.0.1:53"

[transport.tcp]
# Bind address for TCP based transport. 
bind = "127.0.0.1:53"

[transport.dot]
# Bind address for DNS-over-TLS based transport. The standard port for DoT is 853.
bind = "127.0.0.1:853"

# TLS certificate and key paths when using DNS-over-TLS. Required if [transport.dot] is used.
[transport.dot.tls]
cert = "path/to/cert.pem"
key = "path/to/key.pem"

[transport.doh]
# Bind address for DNS-over-HTTPS based transport.
bind = "127.0.0.1:443"
# If true, TLS termination is deferred to a reverse proxy in front of the DNS server. In this mode the server listens 
# for plain HTTP and expects the proxy to enforce HTTPS.
defer-tls = false

# TLS certificate and key paths when using DNS-over-TLS. Required if [transport.doh] is used without deferral.
[transport.doh.tls]
cert = "path/to/cert.pem"
key = "path/to/key.pem"

[metrics]
# Bind address for exposing prometheus metrics.
bind = "127.0.0.1:9100"

[logging]
# Log verbosity (debug, info, warn, error).
level = "info"

```

> [!NOTE]
> Binding to port 53 typically requires elevated privileges. When running locally, you may need to use `sudo`, set
> appropriate capabilities, or bind to a higher port.

From here, pass the configuration file into the `dns serve` command:

```
$ dns serve path/to/config.toml
```

## Policy Lists (Allow / Block)

This server ships with built-in allow and block lists that are compiled into the binary.
These lists are **not user-configurable at runtime**.

The intent is for policy decisions to be:

- Curated and reviewed alongside the source code
- Versioned and reproducible
- Updated through normal binary releases rather than local configuration

Updating the allow or block lists requires upgrading to a newer version of the server.
This ensures that all policy changes are auditable, testable, and consistent across deployments.

### Policy List Sources

The built-in allow and block lists used by this server are derived from publicly available, community-maintained
projects. These sources are not modified at runtime and are incorporated into the binary at build time.

The current list sources include:

#### Block lists

- [dns-blocklists](https://github.com/hagezi/dns-blocklists) (domains/ultimate.txt)

#### Allow lists

- [dns-blocklists](https://github.com/hagezi/dns-blocklists) (share/*)

The exact versions of these lists are pinned and updated alongside server releases.
