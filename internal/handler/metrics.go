package handler

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	dnsQueries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dns",
		Subsystem: "handler",
		Name:      "queries_total",
		Help:      "Total number of DNS queries made via the server",
	}, []string{"qtype"})

	dnsResponses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dns",
		Subsystem: "handler",
		Name:      "responses_total",
		Help:      "Total number of DNS responses returned via the server",
	}, []string{"rcode"})

	dnsBlocked = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "dns",
		Subsystem: "handler",
		Name:      "queries_blocked_total",
		Help:      "Total number of DNS queries blocked by the server",
	})

	dnsUpstreamed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dns",
		Subsystem: "handler",
		Name:      "queries_upstreamed_total",
		Help:      "Total number of DNS queries upstreamed by the server",
	}, []string{"upstream"})

	dnsUpstreamSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "dns",
		Subsystem: "handler",
		Name:      "upstream_rtt_seconds",
		Help:      "A histogram of latencies for upstream dns queries",
	}, []string{"upstream"})
)

func RegisterMetrics(r prometheus.Registerer) {
	r.MustRegister(
		dnsQueries,
		dnsResponses,
		dnsBlocked,
		dnsUpstreamed,
		dnsUpstreamSeconds,
	)
}
