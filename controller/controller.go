/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"sigs.k8s.io/external-dns/registry"
	"sigs.k8s.io/external-dns/source"
)

func prometheusByRecordType(sub string, name_template string, help_template string) map[string]prometheus.Gauge {
	ret := make(map[string]prometheus.Gauge)
	for _, recordType := range endpoint.AllRecordTypes {
		ret[recordType] = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "external_dns",
				Subsystem: sub,
				Name:      fmt.Sprintf(name_template, strings.ToLower(recordType)),
				Help:      fmt.Sprintf(help_template, strings.Title(sub), recordType),
			},
		)

	}
	return ret

}

type prometheusStat struct {
	registryErrorsTotal      prometheus.Counter
	sourceErrorsTotal        prometheus.Counter
	sourceEndpointsTotal     prometheus.Gauge
	registryEndpointsTotal   prometheus.Gauge
	lastSyncTimestamp        prometheus.Gauge
	controllerNoChangesTotal prometheus.Counter
	deprecatedRegistryErrors prometheus.Counter
	deprecatedSourceErrors   prometheus.Counter
	registryByRecordType     map[string]prometheus.Gauge
	sourceByRecordType       map[string]prometheus.Gauge
	verifiedByRecordType     map[string]prometheus.Gauge
}

func newPrometheusStat() *prometheusStat {
	ps := &prometheusStat{
		registryErrorsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "external_dns",
				Subsystem: "registry",
				Name:      "errors_total",
				Help:      "Number of Registry errors.",
			},
		),
		sourceErrorsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "external_dns",
				Subsystem: "source",
				Name:      "errors_total",
				Help:      "Number of Source errors.",
			},
		),
		sourceEndpointsTotal: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "external_dns",
				Subsystem: "source",
				Name:      "endpoints_total",
				Help:      "Number of Endpoints in all sources",
			},
		),
		registryEndpointsTotal: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "external_dns",
				Subsystem: "registry",
				Name:      "endpoints_total",
				Help:      "Number of Endpoints in the registry",
			},
		),
		lastSyncTimestamp: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "external_dns",
				Subsystem: "controller",
				Name:      "last_sync_timestamp_seconds",
				Help:      "Timestamp of last successful sync with the DNS provider",
			},
		),
		controllerNoChangesTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "external_dns",
				Subsystem: "controller",
				Name:      "no_op_runs_total",
				Help:      "Number of reconcile loops ending up with no changes on the DNS provider side.",
			},
		),
		deprecatedRegistryErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Subsystem: "registry",
				Name:      "errors_total",
				Help:      "Number of Registry errors.",
			},
		),
		deprecatedSourceErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Subsystem: "source",
				Name:      "errors_total",
				Help:      "Number of Source errors.",
			},
		),
		registryByRecordType: prometheusByRecordType("registry", "%s_records", "Number of Registry %s records."),
		sourceByRecordType:   prometheusByRecordType("source", "%s_records", "Number of Source %s records."),
		verifiedByRecordType: prometheusByRecordType("controller", "verified_%s_records", "Number of DNS %s-records that exists both in source and registry."),
	}
	prometheus.Register(ps.registryErrorsTotal)
	prometheus.Register(ps.sourceErrorsTotal)
	prometheus.Register(ps.sourceEndpointsTotal)
	prometheus.Register(ps.registryEndpointsTotal)
	prometheus.Register(ps.lastSyncTimestamp)
	prometheus.Register(ps.deprecatedRegistryErrors)
	prometheus.Register(ps.deprecatedSourceErrors)
	prometheus.Register(ps.controllerNoChangesTotal)
	for _, p := range ps.registryByRecordType {
		prometheus.Register(p)
	}
	for _, p := range ps.sourceByRecordType {
		prometheus.Register(p)
	}
	for _, p := range ps.verifiedByRecordType {
		prometheus.Unregister(p)
	}
	return ps
}

func (ps *prometheusStat) unregister() {
	prometheus.Unregister(ps.registryErrorsTotal)
	prometheus.Unregister(ps.sourceErrorsTotal)
	prometheus.Unregister(ps.sourceEndpointsTotal)
	prometheus.Unregister(ps.registryEndpointsTotal)
	prometheus.Unregister(ps.lastSyncTimestamp)
	prometheus.Unregister(ps.deprecatedRegistryErrors)
	prometheus.Unregister(ps.deprecatedSourceErrors)
	prometheus.Unregister(ps.controllerNoChangesTotal)
	for _, p := range ps.registryByRecordType {
		prometheus.Unregister(p)
	}
	for _, p := range ps.sourceByRecordType {
		prometheus.Unregister(p)
	}
	for _, p := range ps.verifiedByRecordType {
		prometheus.Unregister(p)
	}
}

// Controller is responsible for orchestrating the different components.
// It works in the following way:
// * Ask the DNS provider for current list of endpoints.
// * Ask the Source for the desired list of endpoints.
// * Take both lists and calculate a Plan to move current towards desired state.
// * Tell the DNS provider to apply the changes calculated by the Plan.
type Controller struct {
	Source   source.Source
	Registry registry.Registry
	// The policy that defines which changes to DNS records are allowed
	Policy plan.Policy
	// The interval between individual synchronizations
	Interval time.Duration
	// The DomainFilter defines which DNS records to keep or exclude
	DomainFilter endpoint.DomainFilterInterface
	// The nextRunAt used for throttling and batching reconciliation
	nextRunAt time.Time
	// The nextRunAtMux is for atomic updating of nextRunAt
	nextRunAtMux sync.Mutex
	// DNS record types that will be considered for management
	ManagedRecordTypes []string
	// MinEventSyncInterval is used as window for batching events
	MinEventSyncInterval time.Duration

	ps *prometheusStat
}

func StartController(c *Controller) *Controller {
	if c.ps == nil {
		c.ps = newPrometheusStat()
	}
	return c
}

func (c *Controller) Stop() {
	c.ps.unregister()
}

func applyOwnershipRecords(eps []*endpoint.Endpoint) []*endpoint.Endpoint {

	return eps
}

// RunOnce runs a single iteration of a reconciliation loop.
func (c *Controller) RunOnce(ctx context.Context) error {
	records, err := c.Registry.Records(ctx)
	if err != nil {
		c.ps.registryErrorsTotal.Inc()
		c.ps.deprecatedRegistryErrors.Inc()
		return err
	}

	// missingRecords := c.Registry.MissingRecords()

	c.ps.registryEndpointsTotal.Set(float64(len(records)))
	for rt, cnt := range countAddressRecords(records) {
		p, ok := c.ps.registryByRecordType[rt]
		if ok {
			p.Set(float64(cnt))
		}
	}
	ctx = context.WithValue(ctx, provider.RecordsContextKey, records)

	endpoints, err := c.Source.Endpoints(ctx)

	// add ownership records
	endpoints = c.Registry.EnsureOwnerShipRecords(endpoints)

	// let the provider adjust the endpoints
	endpoints = c.Registry.AdjustEndpoints(endpoints)

	if err != nil {
		c.ps.sourceErrorsTotal.Inc()
		c.ps.deprecatedSourceErrors.Inc()
		return err
	}
	c.ps.sourceEndpointsTotal.Set(float64(len(endpoints)))
	for rt, cnt := range countAddressRecords(endpoints) {
		p, ok := c.ps.sourceByRecordType[rt]
		if ok {
			p.Set(float64(cnt))
		}
	}
	for rt, cnt := range countMatchingAddressRecords(endpoints, records) {
		p, ok := c.ps.verifiedByRecordType[rt]
		if ok {
			p.Set(float64(cnt))
		}
	}

	plan := &plan.Plan{
		Policies:           []plan.Policy{c.Policy},
		Current:            records,
		Desired:            endpoints,
		DomainFilter:       endpoint.MatchAllDomainFilters{c.DomainFilter, c.Registry.GetDomainFilter()},
		PropertyComparator: c.Registry.PropertyValuesEqual,
		// we need to add TXT records to the managed records
		// the ownership records are already added to the endpoints
		ManagedRecords: append(c.ManagedRecordTypes, endpoint.RecordTypeTXT),
	}

	plan, err = plan.Calculate()
	if err != nil {
		c.ps.sourceErrorsTotal.Inc()
		c.ps.deprecatedSourceErrors.Inc()
		return err
	}

	if plan.Changes.HasChanges() {
		err = c.Registry.ApplyChanges(ctx, plan.Changes)
		if err != nil {
			c.ps.registryErrorsTotal.Inc()
			c.ps.deprecatedRegistryErrors.Inc()
			return err
		}
	} else {
		c.ps.controllerNoChangesTotal.Inc()
		log.Info("All records are already up to date")
	}

	c.ps.lastSyncTimestamp.SetToCurrentTime()
	return nil
}

// Counts the intersections of A and AAAA records in endpoint and registry.
func countMatchingAddressRecords(endpoints []*endpoint.Endpoint, registryRecords []*endpoint.Endpoint) map[string]int {
	recordsMap := make(map[string]map[string]struct{})
	for _, regRecord := range registryRecords {
		if _, found := recordsMap[regRecord.Name.Fqdn()]; !found {
			recordsMap[regRecord.Name.Fqdn()] = make(map[string]struct{})
		}
		recordsMap[regRecord.Name.Fqdn()][regRecord.RecordType] = struct{}{}
	}
	ret := make(map[string]int)
	for _, sourceRecord := range endpoints {
		if _, found := recordsMap[sourceRecord.Name.Fqdn()]; found {
			if _, found := recordsMap[sourceRecord.Name.Fqdn()][sourceRecord.RecordType]; found {
				ret[sourceRecord.RecordType] = ret[sourceRecord.RecordType] + 1
			}
		}
	}
	return ret
}

func countAddressRecords(endpoints []*endpoint.Endpoint) map[string]int {
	recordsMap := make(map[string]int)
	for _, endPoint := range endpoints {
		recordsMap[endPoint.RecordType] = recordsMap[endPoint.RecordType] + 1
	}
	return recordsMap
}

// ScheduleRunOnce makes sure execution happens at most once per interval.
func (c *Controller) ScheduleRunOnce(now time.Time) {
	c.nextRunAtMux.Lock()
	defer c.nextRunAtMux.Unlock()
	// schedule only if a reconciliation is not already planned
	// to happen in the following c.MinEventSyncInterval
	if !c.nextRunAt.Before(now.Add(c.MinEventSyncInterval)) {
		c.nextRunAt = now.Add(c.MinEventSyncInterval)
	}
}

func (c *Controller) ShouldRunOnce(now time.Time) bool {
	c.nextRunAtMux.Lock()
	defer c.nextRunAtMux.Unlock()
	if now.Before(c.nextRunAt) {
		return false
	}
	c.nextRunAt = now.Add(c.Interval)
	return true
}

// Run runs RunOnce in a loop with a delay until context is canceled
func (c *Controller) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if c.ShouldRunOnce(time.Now()) {
			if err := c.RunOnce(ctx); err != nil {
				log.Fatal(err)
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			log.Info("Terminating main controller loop")
			return
		}
	}
}
