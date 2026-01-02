package list

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	domainsBlocked = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "policy",
		Subsystem: "list",
		Name:      "domains_blocked_total",
		Help:      "Number of blocked domains",
	})

	domainsAllowed = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "policy",
		Subsystem: "list",
		Name:      "domains_allowed_total",
		Help:      "Number of allowed domains",
	})
)

func RegisterMetrics(r prometheus.Registerer) {
	r.MustRegister(domainsBlocked, domainsAllowed)
}
