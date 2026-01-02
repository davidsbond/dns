package cache

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	cacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "dns",
		Subsystem: "cache",
		Name:      "hits_total",
		Help:      "Number of cache hits for DNS entries",
	})

	cacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "dns",
		Subsystem: "cache",
		Name:      "misses_total",
		Help:      "Number of cache misses for DNS entries",
	})
)

func RegisterMetrics(r prometheus.Registerer) {
	r.MustRegister(cacheHits, cacheMisses)
}
