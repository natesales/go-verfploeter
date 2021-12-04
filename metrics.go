package main

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	requests = promauto.NewCounter(prometheus.CounterOpts{
		Name:        "verfploeter_requests",
		ConstLabels: prometheus.Labels{"id": strconv.Itoa(*id)},
	})
	replies = promauto.NewCounter(prometheus.CounterOpts{
		Name:        "verfploeter_replies",
		ConstLabels: prometheus.Labels{"id": strconv.Itoa(*id)},
	})
)

func metricsListen(address string) {
	http.Handle("/metrics", promhttp.Handler())
	log.Infof("Starting exporter: http://%s/metrics", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
