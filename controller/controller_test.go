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
	"errors"
	"math"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	ep "sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/internal/testutils"
	"sigs.k8s.io/external-dns/pkg/apis/externaldns"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"sigs.k8s.io/external-dns/registry"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProvider returns mock endpoints and validates changes.
type mockProvider struct {
	provider.BaseProvider
	RecordsStore  []*ep.Endpoint
	ExpectChanges *plan.Changes
}

type filteredMockProvider struct {
	provider.BaseProvider
	domainFilter      ep.DomainFilterInterface
	RecordsStore      []*ep.Endpoint
	RecordsCallCount  int
	ApplyChangesCalls []*plan.Changes
}

type errorMockProvider struct {
	mockProvider
}

func (p *filteredMockProvider) GetDomainFilter() ep.DomainFilterInterface {
	return p.domainFilter
}

// Records returns the desired mock endpoints.
func (p *filteredMockProvider) Records(ctx context.Context) ([]*ep.Endpoint, error) {
	p.RecordsCallCount++
	return p.RecordsStore, nil
}

// ApplyChanges stores all calls for later check
func (p *filteredMockProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	p.ApplyChangesCalls = append(p.ApplyChangesCalls, changes)
	return nil
}

// Records returns the desired mock endpoints.
func (p *mockProvider) Records(ctx context.Context) ([]*ep.Endpoint, error) {
	return p.RecordsStore, nil
}

func (p *errorMockProvider) Records(ctx context.Context) ([]*ep.Endpoint, error) {
	return nil, errors.New("error for testing")
}

// ApplyChanges validates that the passed in changes satisfy the assumptions.
func (p *mockProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	if err := verifyEndpoints(changes.Create, p.ExpectChanges.Create); err != nil {
		return err
	}

	if err := verifyEndpoints(changes.UpdateNew, p.ExpectChanges.UpdateNew); err != nil {
		return err
	}

	if err := verifyEndpoints(changes.UpdateOld, p.ExpectChanges.UpdateOld); err != nil {
		return err
	}

	if err := verifyEndpoints(changes.Delete, p.ExpectChanges.Delete); err != nil {
		return err
	}

	if !reflect.DeepEqual(ctx.Value(provider.RecordsContextKey), p.RecordsStore) {
		return errors.New("context is wrong")
	}
	return nil
}

func verifyEndpoints(actual, expected []*ep.Endpoint) error {
	if len(actual) != len(expected) {
		return errors.New("number of records is wrong")
	}
	sort.Slice(actual, func(i, j int) bool {
		return actual[i].Name.Fqdn() < actual[j].Name.Fqdn()
	})
	for i := range actual {
		if actual[i].Name.Fqdn() != expected[i].Name.Fqdn() || !actual[i].Targets.Same(expected[i].Targets) {
			return errors.New("record is wrong")
		}
	}
	return nil
}

// newMockProvider creates a new mockProvider returning the given endpoints and validating the desired changes.
func newMockProvider(endpoints []*ep.Endpoint, changes *plan.Changes) provider.Provider {
	dnsProvider := &mockProvider{
		RecordsStore:  endpoints,
		ExpectChanges: changes,
	}

	return dnsProvider
}

// TestRunOnce tests that RunOnce correctly orchestrates the different components.
func TestRunOnce(t *testing.T) {
	// Fake some desired endpoints coming from our source.
	source := new(testutils.MockSource)
	cfg := externaldns.NewConfig()
	cfg.ManagedDNSRecordTypes = []string{ep.RecordTypeA, ep.RecordTypeAAAA, ep.RecordTypeCNAME}
	source.On("Endpoints").Return([]*ep.Endpoint{
		{
			Name:       ep.NewEndpointNameCommon("create-record"),
			RecordType: ep.RecordTypeA,
			Targets:    ep.Targets{"1.2.3.4"},
		},
		{
			Name:       ep.NewEndpointNameCommon("update-record"),
			RecordType: ep.RecordTypeA,
			Targets:    ep.Targets{"8.8.4.4"},
		},
		{
			Name:       ep.NewEndpointNameCommon("create-aaaa-record"),
			RecordType: ep.RecordTypeAAAA,
			Targets:    ep.Targets{"2001:DB8::1"},
		},
		{
			Name:       ep.NewEndpointNameCommon("update-aaaa-record"),
			RecordType: ep.RecordTypeAAAA,
			Targets:    ep.Targets{"2001:DB8::2"},
		},
	}, nil)

	// Fake some existing records in our DNS provider and validate some desired changes.
	provider := newMockProvider(
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("update-record"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
			{
				Name:       ep.NewEndpointNameCommon("delete-record"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"4.3.2.1"},
			},
			{
				Name:       ep.NewEndpointNameCommon("update-aaaa-record"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::3"},
			},
			{
				Name:       ep.NewEndpointNameCommon("delete-aaaa-record"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::4"},
			},
		},
		&plan.Changes{
			Create: []*ep.Endpoint{
				{Name: ep.NewEndpointNameCommon("create-aaaa-record"), RecordType: ep.RecordTypeAAAA, Targets: ep.Targets{"2001:DB8::1"}},
				{Name: ep.NewEndpointNameCommon("create-record"), RecordType: ep.RecordTypeA, Targets: ep.Targets{"1.2.3.4"}},
			},
			UpdateNew: []*ep.Endpoint{
				{Name: ep.NewEndpointNameCommon("update-aaaa-record"), RecordType: ep.RecordTypeAAAA, Targets: ep.Targets{"2001:DB8::2"}},
				{Name: ep.NewEndpointNameCommon("update-record"), RecordType: ep.RecordTypeA, Targets: ep.Targets{"8.8.4.4"}},
			},
			UpdateOld: []*ep.Endpoint{
				{Name: ep.NewEndpointNameCommon("update-aaaa-record"), RecordType: ep.RecordTypeAAAA, Targets: ep.Targets{"2001:DB8::3"}},
				{Name: ep.NewEndpointNameCommon("update-record"), RecordType: ep.RecordTypeA, Targets: ep.Targets{"8.8.8.8"}},
			},
			Delete: []*ep.Endpoint{
				{Name: ep.NewEndpointNameCommon("delete-aaaa-record"), RecordType: ep.RecordTypeAAAA, Targets: ep.Targets{"2001:DB8::4"}},
				{Name: ep.NewEndpointNameCommon("delete-record"), RecordType: ep.RecordTypeA, Targets: ep.Targets{"4.3.2.1"}},
			},
		},
	)

	r, err := registry.NewNoopRegistry(provider)
	require.NoError(t, err)

	// Run our controller once to trigger the validation.
	ctrl := &Controller{
		Source:             source,
		Registry:           r,
		Policy:             &plan.SyncPolicy{},
		ManagedRecordTypes: cfg.ManagedDNSRecordTypes,
		ps:                 newPrometheusStat(),
	}

	assert.NoError(t, ctrl.RunOnce(context.Background()))

	// Validate that the mock source was called.
	source.AssertExpectations(t)
	// check the verified records
	assert.Equal(t, math.Float64bits(1), valueFromMetric(ctrl.ps.verifiedByRecordType[ep.RecordTypeA]))
	assert.Equal(t, math.Float64bits(1), valueFromMetric(ctrl.ps.verifiedByRecordType[ep.RecordTypeAAAA]))
}

func valueFromMetric(metric prometheus.Gauge) uint64 {
	ref := reflect.ValueOf(metric)
	return reflect.Indirect(ref).FieldByName("valBits").Uint()
}

func TestShouldRunOnce(t *testing.T) {
	ctrl := StartController(&Controller{Interval: 10 * time.Minute, MinEventSyncInterval: 5 * time.Second})
	defer ctrl.Stop()

	now := time.Now()

	// First run of Run loop should execute RunOnce
	assert.True(t, ctrl.ShouldRunOnce(now))

	// Second run should not
	assert.False(t, ctrl.ShouldRunOnce(now))

	now = now.Add(10 * time.Second)
	// Changes happen in ingresses or services
	ctrl.ScheduleRunOnce(now)
	ctrl.ScheduleRunOnce(now)

	// Because we batch changes, ShouldRunOnce returns False at first
	assert.False(t, ctrl.ShouldRunOnce(now))
	assert.False(t, ctrl.ShouldRunOnce(now.Add(100*time.Microsecond)))

	// But after MinInterval we should run reconciliation
	now = now.Add(5 * time.Second)
	assert.True(t, ctrl.ShouldRunOnce(now))

	// But just one time
	assert.False(t, ctrl.ShouldRunOnce(now))

	// We should wait maximum possible time after last reconciliation started
	now = now.Add(10*time.Minute - time.Second)
	assert.False(t, ctrl.ShouldRunOnce(now))

	// After exactly Interval it's OK again to reconcile
	now = now.Add(time.Second)
	assert.True(t, ctrl.ShouldRunOnce(now))

	// But not two times
	assert.False(t, ctrl.ShouldRunOnce(now))

	// Multiple ingresses or services changes, closer than MinInterval from each other
	firstChangeTime := now
	secondChangeTime := firstChangeTime.Add(time.Second)
	// First change
	ctrl.ScheduleRunOnce(firstChangeTime)
	// Second change
	ctrl.ScheduleRunOnce(secondChangeTime)
	// Should not postpone the reconciliation further than firstChangeTime + MinInterval
	now = now.Add(ctrl.MinEventSyncInterval)
	assert.True(t, ctrl.ShouldRunOnce(now))
}

func testControllerFiltersDomains(t *testing.T,
	configuredEndpoints []*ep.Endpoint,
	domainFilter ep.DomainFilterInterface,
	providerEndpoints []*ep.Endpoint,
	expectedChanges []*plan.Changes) *Controller {
	t.Helper()
	cfg := externaldns.NewConfig()
	cfg.ManagedDNSRecordTypes = []string{ep.RecordTypeA, ep.RecordTypeAAAA, ep.RecordTypeCNAME}

	source := new(testutils.MockSource)
	source.On("Endpoints").Return(configuredEndpoints, nil)

	// Fake some existing records in our DNS provider and validate some desired changes.
	provider := &filteredMockProvider{
		RecordsStore: providerEndpoints,
	}
	r, err := registry.NewNoopRegistry(provider)

	require.NoError(t, err)

	ctrl := StartController(&Controller{
		Source:             source,
		Registry:           r,
		Policy:             &plan.SyncPolicy{},
		DomainFilter:       domainFilter,
		ManagedRecordTypes: cfg.ManagedDNSRecordTypes,
		ps:                 newPrometheusStat(),
	})

	assert.NoError(t, ctrl.RunOnce(context.Background()))
	assert.Equal(t, 1, provider.RecordsCallCount)
	require.Len(t, provider.ApplyChangesCalls, len(expectedChanges))
	for i, change := range expectedChanges {
		assert.Equal(t, *change, *provider.ApplyChangesCalls[i])
	}
	return ctrl
}

type noopRegistryWithMissing struct {
	*registry.NoopRegistry
	ownerShipRecords []*ep.Endpoint
}

func (r *noopRegistryWithMissing) EnsureOwnerShipRecords(eps []*ep.Endpoint) []*ep.Endpoint {
	return append(eps, r.ownerShipRecords...)
}

func testControllerFiltersDomainsWithMissing(t *testing.T,
	configuredEndpoints []*ep.Endpoint,
	domainFilter ep.DomainFilterInterface,
	providerEndpoints []*ep.Endpoint,
	ownerShipRecords []*ep.Endpoint,
	expectedChanges []*plan.Changes) *Controller {
	t.Helper()
	cfg := externaldns.NewConfig()
	cfg.ManagedDNSRecordTypes = []string{ep.RecordTypeA, ep.RecordTypeCNAME}

	source := new(testutils.MockSource)
	source.On("Endpoints").Return(configuredEndpoints, nil)

	// Fake some existing records in our DNS provider and validate some desired changes.
	provider := &filteredMockProvider{
		RecordsStore: providerEndpoints,
	}
	noop, err := registry.NewNoopRegistry(provider)
	require.NoError(t, err)

	r := &noopRegistryWithMissing{
		NoopRegistry:     noop,
		ownerShipRecords: ownerShipRecords,
	}

	ctrl := StartController(&Controller{
		Source:             source,
		Registry:           r,
		Policy:             &plan.SyncPolicy{},
		DomainFilter:       domainFilter,
		ManagedRecordTypes: cfg.ManagedDNSRecordTypes,
	})

	assert.NoError(t, ctrl.RunOnce(context.Background()))
	assert.Equal(t, 1, provider.RecordsCallCount)
	require.Len(t, provider.ApplyChangesCalls, 1)
	for _, change := range expectedChanges {
		require.Len(t, change.Create, 2)
		require.Len(t, change.Delete, 0)
		require.Len(t, change.UpdateNew, 0)
		require.Len(t, change.UpdateOld, 0)
		testutils.SortEndpoints(change.Create)
		testutils.SortEndpoints(provider.ApplyChangesCalls[0].Create)
		assert.Equal(t, change.Create, provider.ApplyChangesCalls[0].Create)
	}
	return ctrl
}

func TestControllerSkipsEmptyChanges(t *testing.T) {
	testControllerFiltersDomains(
		t,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("create-record.other.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
		},
		ep.NewDomainFilter([]string{"used.tld"}),
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
		},
		[]*plan.Changes{},
	).Stop()
}

func TestWhenNoFilterControllerConsidersAllComain(t *testing.T) {
	testControllerFiltersDomains(
		t,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("create-record.other.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
		},
		nil,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
		},
		[]*plan.Changes{
			{
				Create: []*ep.Endpoint{
					{
						Name:       ep.NewEndpointNameCommon("create-record.other.tld"),
						RecordType: ep.RecordTypeA,
						Targets:    ep.Targets{"1.2.3.4"},
					},
				},
			},
		},
	).Stop()
}

func TestWhenMultipleControllerConsidersAllFilteredComain(t *testing.T) {
	testControllerFiltersDomains(
		t,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("create-record.other.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.1.1.1"},
				Labels: map[string]string{
					"owner": "me",
				},
			},
			{
				Name:       ep.NewEndpointNameCommon("create-record.unused.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
		},
		ep.NewDomainFilter([]string{"used.tld", "other.tld"}),
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
		},
		[]*plan.Changes{
			{
				Create: []*ep.Endpoint{
					{
						Name:       ep.NewEndpointNameCommon("create-record.other.tld"),
						RecordType: ep.RecordTypeA,
						Targets:    ep.Targets{"1.2.3.4"},
					},
				},
				UpdateOld: []*ep.Endpoint{
					{
						Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
						RecordType: ep.RecordTypeA,
						Targets:    ep.Targets{"8.8.8.8"},
					},
				},
				UpdateNew: []*ep.Endpoint{
					{
						Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
						RecordType: ep.RecordTypeA,
						Targets:    ep.Targets{"1.1.1.1"},
						// this ne new resolver will transfer existing labels
						Labels: ep.Labels{
							"owner": "me",
						},
					},
				},
			},
		},
	).Stop()
}

func TestVerifyARecords(t *testing.T) {
	ctrl := testControllerFiltersDomains(
		t,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("create-record.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
		},
		ep.NewDomainFilter([]string{"used.tld"}),
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
			{
				Name:       ep.NewEndpointNameCommon("create-record.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
		},
		[]*plan.Changes{},
	)
	assert.Equal(t, math.Float64bits(2), valueFromMetric(ctrl.ps.verifiedByRecordType[ep.RecordTypeA]))
	ctrl.Stop()

	ctrl = testControllerFiltersDomains(
		t,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("some-record.1.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.2.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.3.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"24.24.24.24"},
			},
		},
		ep.NewDomainFilter([]string{"used.tld"}),
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("some-record.1.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.2.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
		},
		[]*plan.Changes{{
			Create: []*ep.Endpoint{
				{
					Name:       ep.NewEndpointNameCommon("some-record.3.used.tld"),
					RecordType: ep.RecordTypeA,
					Targets:    ep.Targets{"24.24.24.24"},
				},
			},
		}},
	)
	assert.Equal(t, math.Float64bits(2), valueFromMetric(ctrl.ps.verifiedByRecordType["A"]))
	assert.Equal(t, math.Float64bits(0), valueFromMetric(ctrl.ps.verifiedByRecordType["AAAA"]))
	ctrl.Stop()
}

func TestVerifyAAAARecords(t *testing.T) {
	ctrl := testControllerFiltersDomains(
		t,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("create-record.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::1"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::2"},
			},
		},
		ep.NewDomainFilter([]string{"used.tld"}),
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("some-record.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::2"},
			},
			{
				Name:       ep.NewEndpointNameCommon("create-record.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::1"},
			},
		},
		[]*plan.Changes{},
	)
	ctrl.Stop()
	assert.Equal(t, math.Float64bits(2), valueFromMetric(ctrl.ps.verifiedByRecordType[ep.RecordTypeAAAA]))

	ctrl = testControllerFiltersDomains(
		t,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("some-record.1.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::1"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.2.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::2"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.3.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::3"},
			},
		},
		ep.NewDomainFilter([]string{"used.tld"}),
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("some-record.1.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::1"},
			},
			{
				Name:       ep.NewEndpointNameCommon("some-record.2.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::2"},
			},
		},
		[]*plan.Changes{{
			Create: []*ep.Endpoint{
				{
					Name:       ep.NewEndpointNameCommon("some-record.3.used.tld"),
					RecordType: ep.RecordTypeAAAA,
					Targets:    ep.Targets{"2001:DB8::3"},
				},
			},
		}},
	)
	ctrl.Stop()
	assert.Equal(t, math.Float64bits(0), valueFromMetric(ctrl.ps.verifiedByRecordType[ep.RecordTypeA]))
	assert.Equal(t, math.Float64bits(2), valueFromMetric(ctrl.ps.verifiedByRecordType[ep.RecordTypeAAAA]))
}

func TestARecords(t *testing.T) {
	ctrl := testControllerFiltersDomains(
		t,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("record1.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
			{
				Name:       ep.NewEndpointNameCommon("record2.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
			{
				Name:       ep.NewEndpointNameCommon("_mysql-svc._tcp.mysql.used.tld"),
				RecordType: ep.RecordTypeSRV,
				Targets:    ep.Targets{"0 50 30007 mysql.used.tld"},
			},
		},
		ep.NewDomainFilter([]string{"used.tld"}),
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("record1.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
			{
				Name:       ep.NewEndpointNameCommon("_mysql-svc._tcp.mysql.used.tld"),
				RecordType: ep.RecordTypeSRV,
				Targets:    ep.Targets{"0 50 30007 mysql.used.tld"},
			},
		},
		[]*plan.Changes{{
			Create: []*ep.Endpoint{
				{
					Name:       ep.NewEndpointNameCommon("record2.used.tld"),
					RecordType: ep.RecordTypeA,
					Targets:    ep.Targets{"8.8.8.8"},
				},
			},
		}},
	)
	ctrl.Stop()
	assert.Equal(t, math.Float64bits(2), valueFromMetric(ctrl.ps.sourceByRecordType[ep.RecordTypeA]))
	assert.Equal(t, math.Float64bits(1), valueFromMetric(ctrl.ps.registryByRecordType[ep.RecordTypeA]))
}

// TestMissingRecordsApply validates that the missing records result in the dedicated plan apply.
func TestMissingRecordsApply(t *testing.T) {
	testControllerFiltersDomainsWithMissing(
		t,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("record1.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
			{
				Name:       ep.NewEndpointNameCommon("record2.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"8.8.8.8"},
			},
		},
		ep.NewDomainFilter([]string{"used.tld"}),
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("record1.used.tld"),
				RecordType: ep.RecordTypeA,
				Targets:    ep.Targets{"1.2.3.4"},
			},
		},
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("a-record1.used.tld"),
				RecordType: ep.RecordTypeTXT,
				Targets:    ep.Targets{"\"heritage=external-dns,external-dns/owner=owner\""},
			},
		},
		[]*plan.Changes{
			// Missing record had its own plan applied.
			{
				Create: []*ep.Endpoint{
					{
						Name:       ep.NewEndpointNameCommon("a-record1.used.tld"),
						RecordType: ep.RecordTypeTXT,
						Targets:    ep.Targets{"\"heritage=external-dns,external-dns/owner=owner\""},
					},
					{
						Name:       ep.NewEndpointNameCommon("record2.used.tld"),
						RecordType: ep.RecordTypeA,
						Targets:    ep.Targets{"8.8.8.8"},
					},
				},
			},
		}).Stop()
}

func TestAAAARecords(t *testing.T) {
	ctrl := testControllerFiltersDomains(
		t,
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("record1.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::1"},
			},
			{
				Name:       ep.NewEndpointNameCommon("record2.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::2"},
			},
			{
				Name:       ep.NewEndpointNameCommon("_mysql-svc._tcp.mysql.used.tld"),
				RecordType: ep.RecordTypeSRV,
				Targets:    ep.Targets{"0 50 30007 mysql.used.tld"},
			},
		},
		ep.NewDomainFilter([]string{"used.tld"}),
		[]*ep.Endpoint{
			{
				Name:       ep.NewEndpointNameCommon("record1.used.tld"),
				RecordType: ep.RecordTypeAAAA,
				Targets:    ep.Targets{"2001:DB8::1"},
			},
			{
				Name:       ep.NewEndpointNameCommon("_mysql-svc._tcp.mysql.used.tld"),
				RecordType: ep.RecordTypeSRV,
				Targets:    ep.Targets{"0 50 30007 mysql.used.tld"},
			},
		},
		[]*plan.Changes{{
			Create: []*ep.Endpoint{
				{
					Name:       ep.NewEndpointNameCommon("record2.used.tld"),
					RecordType: ep.RecordTypeAAAA,
					Targets:    ep.Targets{"2001:DB8::2"},
				},
			},
		}},
	)
	assert.Equal(t, math.Float64bits(2), valueFromMetric(ctrl.ps.sourceByRecordType[ep.RecordTypeAAAA]))
	assert.Equal(t, math.Float64bits(1), valueFromMetric(ctrl.ps.registryByRecordType[ep.RecordTypeAAAA]))
	ctrl.Stop()
}
