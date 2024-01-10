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

package plan

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/internal/testutils"
	"sigs.k8s.io/external-dns/provider/inmemory"
)

type PlanTestSuite struct {
	suite.Suite
	fooV1Cname                       *endpoint.Endpoint
	fooV2Cname                       *endpoint.Endpoint
	fooV1MX                          *endpoint.Endpoint
	fooV2MX                          *endpoint.Endpoint
	fooV1V2MX                        *endpoint.Endpoint
	fooV2MXNoLabel                   *endpoint.Endpoint
	fooV2CnameUppercase              *endpoint.Endpoint
	fooV2TXT                         *endpoint.Endpoint
	fooV2CnameNoLabel                *endpoint.Endpoint
	fooV3CnameSameResource           *endpoint.Endpoint
	fooA5                            *endpoint.Endpoint
	fooAAAA                          *endpoint.Endpoint
	dsA                              *endpoint.Endpoint
	dsAAAA                           *endpoint.Endpoint
	bar127A                          *endpoint.Endpoint
	bar127AWithTTL                   *endpoint.Endpoint
	bar127AWithProviderSpecificTrue  *endpoint.Endpoint
	bar127AWithProviderSpecificFalse *endpoint.Endpoint
	bar127AWithProviderSpecificUnset *endpoint.Endpoint
	bar192A                          *endpoint.Endpoint
	multiple1                        *endpoint.Endpoint
	multiple2                        *endpoint.Endpoint
	multiple3                        *endpoint.Endpoint
	domainFilterFiltered1            *endpoint.Endpoint
	domainFilterFiltered2            *endpoint.Endpoint
	domainFilterFiltered3            *endpoint.Endpoint
	domainFilterExcluded             *endpoint.Endpoint
	domainFilterFilteredTXT1         *endpoint.Endpoint
	domainFilterFilteredTXT2         *endpoint.Endpoint
	domainFilterExcludedTXT          *endpoint.Endpoint
	managedRecordTypes               []string
}

func (suite *PlanTestSuite) SetupTest() {
	suite.managedRecordTypes = []string{
		endpoint.RecordTypeA,
		endpoint.RecordTypeCNAME,
		endpoint.RecordTypeTXT, // for the heritage TXT record
		endpoint.RecordTypeMX,
	}
	suite.fooV1Cname = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"v1"},
		RecordType: "CNAME",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-v1",
			endpoint.OwnerLabelKey:    "pwner",
		},
	}
	suite.fooV1MX = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"v1"},
		RecordType: "MX",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-v1",
			endpoint.OwnerLabelKey:    "pwner",
		},
	}
	suite.fooV2MX = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"v2"},
		RecordType: "MX",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-v1",
			endpoint.OwnerLabelKey:    "pwner",
		},
	}
	suite.fooV1V2MX = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"v1", "v2"},
		RecordType: "MX",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-v1",
			endpoint.OwnerLabelKey:    "pwner",
		},
	}
	// same resource as fooV1Cname, but target is different. It will never be picked because its target lexicographically bigger than "v1"
	suite.fooV3CnameSameResource = &endpoint.Endpoint{ // TODO: remove this once endpoint can support multiple targets
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"v3"},
		RecordType: "CNAME",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-v1",
			endpoint.OwnerLabelKey:    "pwner",
		},
	}
	suite.fooV2Cname = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"v2"},
		RecordType: "CNAME",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-v2",
		},
	}
	suite.fooV2CnameUppercase = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"V2"},
		RecordType: "CNAME",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-v2",
		},
	}
	suite.fooV2TXT = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		RecordType: "TXT",
	}
	suite.fooV2MXNoLabel = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"v2"},
		RecordType: "MX",
	}
	suite.fooV2CnameNoLabel = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"v2"},
		RecordType: "CNAME",
	}
	suite.fooA5 = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"5.5.5.5"},
		RecordType: "A",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-5",
		},
	}
	suite.fooAAAA = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo"),
		Targets:    endpoint.Targets{"2001:DB8::1"},
		RecordType: "AAAA",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/foo-AAAA",
		},
	}
	suite.dsA = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("ds"),
		Targets:    endpoint.Targets{"1.1.1.1"},
		RecordType: "A",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/ds",
		},
	}
	suite.dsAAAA = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("ds"),
		Targets:    endpoint.Targets{"1.1.1.1"},
		RecordType: "AAAA",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/ds-AAAAA",
		},
	}
	suite.bar127A = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("bar"),
		Targets:    endpoint.Targets{"127.0.0.1"},
		RecordType: "A",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/bar-127",
		},
	}
	suite.bar127AWithTTL = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("bar"),
		Targets:    endpoint.Targets{"127.0.0.1"},
		RecordType: "A",
		RecordTTL:  300,
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/bar-127",
		},
	}
	suite.bar127AWithProviderSpecificTrue = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("bar"),
		Targets:    endpoint.Targets{"127.0.0.1"},
		RecordType: "A",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/bar-127",
		},
		ProviderSpecific: endpoint.ProviderSpecific{
			endpoint.ProviderSpecificProperty{
				Name:  "external-dns.alpha.kubernetes.io/cloudflare-proxied",
				Value: "true",
			},
		},
	}
	suite.bar127AWithProviderSpecificFalse = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("bar"),
		Targets:    endpoint.Targets{"127.0.0.1"},
		RecordType: "A",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/bar-127",
		},
		ProviderSpecific: endpoint.ProviderSpecific{
			endpoint.ProviderSpecificProperty{
				Name:  "external-dns.alpha.kubernetes.io/cloudflare-proxied",
				Value: "false",
			},
		},
	}
	suite.bar127AWithProviderSpecificUnset = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("bar"),
		Targets:    endpoint.Targets{"127.0.0.1"},
		RecordType: "A",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/bar-127",
		},
		ProviderSpecific: endpoint.ProviderSpecific{},
	}
	suite.bar192A = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("bar"),
		Targets:    endpoint.Targets{"192.168.0.1"},
		RecordType: "A",
		Labels: map[string]string{
			endpoint.ResourceLabelKey: "ingress/default/bar-192",
		},
	}
	suite.multiple1 = &endpoint.Endpoint{
		Name:          endpoint.NewEndpointNameCommon("multiple"),
		Targets:       endpoint.Targets{"192.168.0.1"},
		RecordType:    "A",
		SetIdentifier: "test-set-1",
	}
	suite.multiple2 = &endpoint.Endpoint{
		Name:          endpoint.NewEndpointNameCommon("multiple"),
		Targets:       endpoint.Targets{"192.168.0.2"},
		RecordType:    "A",
		SetIdentifier: "test-set-1",
	}
	suite.multiple3 = &endpoint.Endpoint{
		Name:          endpoint.NewEndpointNameCommon("multiple"),
		Targets:       endpoint.Targets{"192.168.0.2"},
		RecordType:    "A",
		SetIdentifier: "test-set-2",
	}
	suite.domainFilterFiltered1 = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo.domain.tld"),
		Targets:    endpoint.Targets{"1.2.3.4"},
		RecordType: "A",
	}
	suite.domainFilterFiltered2 = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("bar.domain.tld"),
		Targets:    endpoint.Targets{"1.2.3.5"},
		RecordType: "A",
	}
	suite.domainFilterFiltered3 = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("baz.domain.tld"),
		Targets:    endpoint.Targets{"1.2.3.6"},
		RecordType: "A",
	}
	suite.domainFilterExcluded = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo.ex.domain.tld"),
		Targets:    endpoint.Targets{"1.1.1.1"},
		RecordType: "A",
	}
	suite.domainFilterFilteredTXT1 = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("a-foo.domain.tld"),
		Targets:    endpoint.Targets{"\"heritage=external-dns,external-dns/owner=owner\""},
		RecordType: "TXT",
	}
	suite.domainFilterFilteredTXT2 = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("cname-bar.domain.tld"),
		Targets:    endpoint.Targets{"\"heritage=external-dns,external-dns/owner=owner\""},
		RecordType: "TXT",
	}
	suite.domainFilterExcludedTXT = &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("cname-bar.otherdomain.tld"),
		Targets:    endpoint.Targets{"\"heritage=external-dns,external-dns/owner=owner\""},
		RecordType: "TXT",
	}
}

func (suite *PlanTestSuite) TestSyncFirstRound() {
	current := []*endpoint.Endpoint{}
	desired := []*endpoint.Endpoint{suite.fooV1MX, suite.fooV2MX, suite.bar127A}
	expectedCreate := []*endpoint.Endpoint{suite.fooV1V2MX, suite.bar127A} // v1 is chosen because of resolver taking "min"
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRound() {
	current := []*endpoint.Endpoint{suite.fooV1MX}
	desired := []*endpoint.Endpoint{suite.fooV2MX, suite.fooV1MX, suite.bar127A}
	expectedCreate := []*endpoint.Endpoint{suite.bar127A}
	expectedUpdateOld := []*endpoint.Endpoint{suite.fooV1MX}
	expectedUpdateNew := []*endpoint.Endpoint{suite.fooV1V2MX}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRoundMigration() {
	current := []*endpoint.Endpoint{suite.fooV2MXNoLabel}
	desired := []*endpoint.Endpoint{suite.fooV2MX, suite.fooV1MX, suite.bar127A}
	expectedCreate := []*endpoint.Endpoint{suite.bar127A}
	expectedUpdateOld := []*endpoint.Endpoint{suite.fooV2MXNoLabel}
	expectedUpdateNew := []*endpoint.Endpoint{suite.fooV1V2MX}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRoundWithTTLChange() {
	current := []*endpoint.Endpoint{suite.bar127A}
	desired := []*endpoint.Endpoint{suite.bar127AWithTTL}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{suite.bar127A}
	expectedUpdateNew := []*endpoint.Endpoint{suite.bar127AWithTTL}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRoundWithProviderSpecificChange() {
	current := []*endpoint.Endpoint{suite.bar127AWithProviderSpecificTrue}
	desired := []*endpoint.Endpoint{suite.bar127AWithProviderSpecificFalse}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{suite.bar127AWithProviderSpecificTrue}
	expectedUpdateNew := []*endpoint.Endpoint{suite.bar127AWithProviderSpecificFalse}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRoundWithProviderSpecificDefaultFalse() {
	current := []*endpoint.Endpoint{suite.bar127AWithProviderSpecificFalse}
	desired := []*endpoint.Endpoint{suite.bar127AWithProviderSpecificUnset}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{suite.bar127AWithProviderSpecificFalse}
	expectedUpdateNew := []*endpoint.Endpoint{suite.bar127AWithProviderSpecificUnset}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
		PropertyComparator: func(name, previous, current string) bool {
			return CompareBoolean(false, name, previous, current)
		},
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRoundWithProviderSpecificDefualtTrue() {
	current := []*endpoint.Endpoint{suite.bar127AWithProviderSpecificTrue}
	desired := []*endpoint.Endpoint{suite.bar127AWithProviderSpecificUnset}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
		PropertyComparator: func(name, previous, current string) bool {
			return CompareBoolean(true, name, previous, current)
		},
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSyncSecondRoundWithOwnerInherited() {
	current := []*endpoint.Endpoint{suite.fooV1Cname}
	desired := []*endpoint.Endpoint{suite.fooV2Cname}

	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedUpdateNew := []*endpoint.Endpoint{{
		Name:       suite.fooV2Cname.Name,
		Targets:    suite.fooV2Cname.Targets,
		RecordType: suite.fooV2Cname.RecordType,
		RecordTTL:  suite.fooV2Cname.RecordTTL,
		Labels: map[string]string{
			endpoint.ResourceLabelKey: suite.fooV2Cname.Labels[endpoint.ResourceLabelKey],
			endpoint.OwnerLabelKey:    suite.fooV1Cname.Labels[endpoint.OwnerLabelKey],
		},
	}}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestIdempotency() {
	current := []*endpoint.Endpoint{suite.fooV1Cname, suite.fooV2Cname}
	desired := []*endpoint.Endpoint{suite.fooV1Cname, suite.fooV2Cname}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestDifferentTypes() {
	current := []*endpoint.Endpoint{suite.fooV1Cname}
	desired := []*endpoint.Endpoint{suite.fooV2Cname, suite.fooA5}
	expectedCreate := []*endpoint.Endpoint{suite.fooA5}
	expectedUpdateOld := []*endpoint.Endpoint{suite.fooV1Cname}
	mergedLabels := suite.fooV2Cname.DeepCopy()
	mergedLabels.Labels["owner"] = "pwner"
	expectedUpdateNew := []*endpoint.Endpoint{mergedLabels}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestIgnoreTXT() {
	current := []*endpoint.Endpoint{suite.fooV2TXT}
	desired := []*endpoint.Endpoint{suite.fooV2Cname}
	expectedCreate := []*endpoint.Endpoint{suite.fooV2Cname}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestIgnoreTargetCase() {
	current := []*endpoint.Endpoint{suite.fooV2Cname}
	desired := []*endpoint.Endpoint{suite.fooV2CnameUppercase}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  current,
		Desired:  desired,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestRemoveEndpoint() {
	current := []*endpoint.Endpoint{suite.fooV1Cname, suite.bar192A}
	desired := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{suite.bar192A}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestRemoveEndpointWithUpsert() {
	current := []*endpoint.Endpoint{suite.fooV1Cname, suite.bar192A}
	desired := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&UpsertOnlyPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestDuplicatedEndpointsInconsitantCNAMES() {
	current := []*endpoint.Endpoint{suite.fooV3CnameSameResource, suite.bar192A}
	// multiple targets for CNAME will be stripped and the last will be used
	desired := []*endpoint.Endpoint{suite.fooV1Cname, suite.fooV3CnameSameResource}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	_, err := p.Calculate()
	suite.ErrorContains(err, "inconsistent targets")
}

func (suite *PlanTestSuite) TestDuplicatedEndpointsForSameResourceReplace() {
	current := []*endpoint.Endpoint{suite.fooV3CnameSameResource, suite.bar192A}
	desired := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{suite.fooV3CnameSameResource}
	expectedUpdateNew := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedDelete := []*endpoint.Endpoint{suite.bar192A}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

// TODO: remove once multiple-target per endpoint is supported
func (suite *PlanTestSuite) TestDuplicatedEndpointsForSameResourceRetain() {
	current := []*endpoint.Endpoint{suite.fooV1Cname, suite.bar192A}
	desired := []*endpoint.Endpoint{suite.fooV1Cname}
	expectedCreate := []*endpoint.Endpoint{}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{suite.bar192A}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestMultipleRecordsSameNameDifferentSetIdentifier() {
	current := []*endpoint.Endpoint{suite.multiple1}
	desired := []*endpoint.Endpoint{suite.multiple2, suite.multiple3}
	expectedCreate := []*endpoint.Endpoint{suite.multiple3}
	expectedUpdateOld := []*endpoint.Endpoint{suite.multiple1}
	expectedUpdateNew := []*endpoint.Endpoint{suite.multiple2}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestSetIdentifierUpdateCreatesAndDeletes() {
	current := []*endpoint.Endpoint{suite.multiple2}
	desired := []*endpoint.Endpoint{suite.multiple3}
	expectedCreate := []*endpoint.Endpoint{suite.multiple3}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{suite.multiple2}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestDomainFiltersInitial() {
	current := []*endpoint.Endpoint{suite.domainFilterExcluded}
	desired := []*endpoint.Endpoint{suite.domainFilterExcluded, suite.domainFilterFiltered1, suite.domainFilterFiltered2, suite.domainFilterFiltered3}
	expectedCreate := []*endpoint.Endpoint{suite.domainFilterFiltered1, suite.domainFilterFiltered2, suite.domainFilterFiltered3}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		DomainFilter:   endpoint.NewDomainFilterWithExclusions([]string{"domain.tld"}, []string{"ex.domain.tld"}),
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestDomainFiltersUpdate() {
	current := []*endpoint.Endpoint{suite.domainFilterExcluded, suite.domainFilterFiltered1, suite.domainFilterFiltered2}
	desired := []*endpoint.Endpoint{suite.domainFilterExcluded, suite.domainFilterFiltered1, suite.domainFilterFiltered2, suite.domainFilterFiltered3}
	expectedCreate := []*endpoint.Endpoint{suite.domainFilterFiltered3}
	expectedUpdateOld := []*endpoint.Endpoint{}
	expectedUpdateNew := []*endpoint.Endpoint{}
	expectedDelete := []*endpoint.Endpoint{}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		DomainFilter:   endpoint.NewDomainFilterWithExclusions([]string{"domain.tld"}, []string{"ex.domain.tld"}),
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
	validateEntries(suite.T(), changes.UpdateNew, expectedUpdateNew)
	validateEntries(suite.T(), changes.UpdateOld, expectedUpdateOld)
	validateEntries(suite.T(), changes.Delete, expectedDelete)
}

func (suite *PlanTestSuite) TestOwnerShipRecords() {
	planeRecords := []*endpoint.Endpoint{
		suite.domainFilterFilteredTXT1,
		suite.domainFilterFilteredTXT2,
	}

	expectedCreate := []*endpoint.Endpoint{
		suite.domainFilterFilteredTXT1,
		suite.domainFilterFilteredTXT2,
	}

	p := &Plan{
		Policies: []Policy{&SyncPolicy{}},
		Current:  []*endpoint.Endpoint{},
		Desired:  planeRecords,
		// Missing:        missing,
		DomainFilter:   endpoint.NewDomainFilter([]string{"domain.tld"}),
		ManagedRecords: suite.managedRecordTypes,
	}

	result, err := p.Calculate()
	suite.Nil(err)
	changes := result.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
}

func (suite *PlanTestSuite) TestAAAARecords() {

	current := []*endpoint.Endpoint{}
	desired := []*endpoint.Endpoint{suite.fooAAAA}
	expectedCreate := []*endpoint.Endpoint{suite.fooAAAA}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: []string{endpoint.RecordTypeAAAA, endpoint.RecordTypeCNAME},
	}

	plan, err := p.Calculate()
	suite.Nil(err)
	changes := plan.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
}

func (suite *PlanTestSuite) TestDualStackRecords() {
	current := []*endpoint.Endpoint{}
	desired := []*endpoint.Endpoint{suite.dsA, suite.dsAAAA}
	expectedCreate := []*endpoint.Endpoint{suite.dsA, suite.dsAAAA}

	p := &Plan{
		Policies:       []Policy{&SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: []string{endpoint.RecordTypeA, endpoint.RecordTypeAAAA, endpoint.RecordTypeCNAME},
	}

	plan, err := p.Calculate()
	suite.Nil(err)
	changes := plan.Changes
	validateEntries(suite.T(), changes.Create, expectedCreate)
}

func TestPlan(t *testing.T) {
	suite.Run(t, new(PlanTestSuite))
}

// validateEntries validates that the list of entries matches expected.
func validateEntries(t *testing.T, entries, expected []*endpoint.Endpoint) {
	require.Len(t, entries, len(expected))
	testutils.SortEndpoints(entries)
	testutils.SortEndpoints(expected)
	for i, e := range entries {
		assert.Equal(t, e, expected[i])
	}
	//if !testutils.SameEndpoints(entries, expected) {
	//	t.Fatalf("expected %q to match %q", entries, expected)
	//}
}

func TestNormalizeDNSName(t *testing.T) {
	records := []struct {
		dnsName string
		expect  string
	}{
		{
			"3AAAA.FOO.BAR.COM    ",
			"3aaaa.foo.bar.com",
		},
		{
			"   example.foo.com.",
			"example.foo.com",
		},
		{
			"example123.foo.com ",
			"example123.foo.com",
		},
		{
			"foo",
			"foo",
		},
		{
			"123foo.bar",
			"123foo.bar",
		},
		{
			"foo.com",
			"foo.com",
		},
		{
			"foo.com.",
			"foo.com",
		},
		{
			"foo123.COM",
			"foo123.com",
		},
		{
			"my-exaMple3.FOO.BAR.COM",
			"my-example3.foo.bar.com",
		},
		{
			"   my-example1214.FOO-1235.BAR-foo.COM   ",
			"my-example1214.foo-1235.bar-foo.com",
		},
		{
			"my-example-my-example-1214.FOO-1235.BAR-foo.COM",
			"my-example-my-example-1214.foo-1235.bar-foo.com",
		},
	}
	for _, r := range records {
		t.Run(r.dnsName, func(t *testing.T) {
			gotName := normalizeDNSName(r.dnsName)
			assert.Equal(t, r.expect, gotName)
		})
	}
}

func TestShouldUpdateProviderSpecific(tt *testing.T) {
	comparator := func(name, previous, current string) bool {
		return previous == current
	}
	for _, test := range []struct {
		name               string
		current            *endpoint.Endpoint
		desired            *endpoint.Endpoint
		propertyComparator func(name, previous, current string) bool
		shouldUpdate       bool
	}{
		{
			name: "skip AWS target health",
			current: &endpoint.Endpoint{
				Name: endpoint.NewEndpointNameCommon("foo.com"),
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "aws/evaluate-target-health", Value: "true"},
				},
			},
			desired: &endpoint.Endpoint{
				Name: endpoint.NewEndpointNameCommon("bar.com"),
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "aws/evaluate-target-health", Value: "true"},
				},
			},
			propertyComparator: comparator,
			shouldUpdate:       false,
		},
		{
			name: "custom property unchanged",
			current: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "custom/property", Value: "true"},
				},
			},
			desired: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "custom/property", Value: "true"},
				},
			},
			propertyComparator: comparator,
			shouldUpdate:       false,
		},
		{
			name: "custom property value changed",
			current: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "custom/property", Value: "true"},
				},
			},
			desired: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "custom/property", Value: "false"},
				},
			},
			propertyComparator: comparator,
			shouldUpdate:       true,
		},
		{
			name: "custom property key changed",
			current: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "custom/property", Value: "true"},
				},
			},
			desired: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "new/property", Value: "true"},
				},
			},
			propertyComparator: comparator,
			shouldUpdate:       true,
		},
		{
			name: "desired has same key and value as current but not comparator is set",
			current: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "custom/property", Value: "true"},
				},
			},
			desired: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "custom/property", Value: "true"},
				},
			},
			shouldUpdate: false,
		},
		{
			name: "desired has same key and different value as current but not comparator is set",
			current: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "custom/property", Value: "true"},
				},
			},
			desired: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "custom/property", Value: "false"},
				},
			},
			shouldUpdate: true,
		},
		{
			name: "desired has different key from current but not comparator is set",
			current: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "custom/property", Value: "true"},
				},
			},
			desired: &endpoint.Endpoint{
				ProviderSpecific: []endpoint.ProviderSpecificProperty{
					{Name: "new/property", Value: "true"},
				},
			},
			shouldUpdate: true,
		},
	} {
		tt.Run(test.name, func(t *testing.T) {
			plan := &Plan{
				Current:            []*endpoint.Endpoint{test.current},
				Desired:            []*endpoint.Endpoint{test.desired},
				PropertyComparator: test.propertyComparator,
				ManagedRecords:     []string{endpoint.RecordTypeA, endpoint.RecordTypeCNAME},
			}
			b := plan.shouldUpdateProviderSpecific(test.desired, test.current)
			assert.Equal(t, test.shouldUpdate, b)
		})
	}
}

func TestPlanSanitize(t *testing.T) {
	pt := newPlanTable()
	toFix := &endpoint.Endpoint{
		Name:          endpoint.NewEndpointNameCommon(" foo.bar.com.  "),
		RecordType:    "   a   ",
		SetIdentifier: " Seti ",
	}
	ok := &endpoint.Endpoint{
		Name:          endpoint.NewEndpointNameCommon("foo.bar.com"),
		RecordType:    "A",
		SetIdentifier: "Seti",
	}
	pt.addCurrent(toFix)
	pt.addCurrent(ok)
	pt.addCandidate(toFix)
	pt.addCandidate(ok)

	for _, ptr := range pt.rows {
		assert.Equal(t, ptr.currents, []*endpoint.Endpoint{ok, ok})
		assert.Equal(t, ptr.candidates, []*endpoint.Endpoint{ok, ok})
	}
}

func TestRemoveUnownedRecords(t *testing.T) {
	registry := []*endpoint.Endpoint{
		newEndpointWithOwner("old-not-owned.foo.co", "new-foo.loadbalancer.com", endpoint.RecordTypeA, "not-owner"),
		newEndpointWithOwnerAndLabels("pre-old-not-owned.foo.co", "xxx", endpoint.RecordTypeTXT, "not-owner",
			endpoint.Labels{endpoint.OwnedRecordLabelKey: "old-not-owned.foo.co"}),

		newEndpointWithOwner("not-owned.foo.co", "new-foo.loadbalancer.com", endpoint.RecordTypeCNAME, "not-owner"),
		newEndpointWithOwnerAndLabels("pre-cname-not-owned.foo.co", "xxx", endpoint.RecordTypeTXT, "not-owner",
			endpoint.Labels{endpoint.OwnedRecordLabelKey: "not-owned.foo.co"}),

		newEndpointWithOwner("old-owned.foo.co", "new-foo.loadbalancer.com", endpoint.RecordTypeA, "owner"),
		newEndpointWithOwnerAndLabels("pre-old-owned.foo.co", "xxx", endpoint.RecordTypeTXT, "owner",
			endpoint.Labels{endpoint.OwnedRecordLabelKey: "old-owned.foo.co"}),

		newEndpointWithOwner("owned.foo.co", "new-foo.loadbalancer.com", endpoint.RecordTypeA, "owner"),
		newEndpointWithOwnerAndLabels("pre-a-owned.foo.co", "xxx", endpoint.RecordTypeTXT, "owner",
			endpoint.Labels{endpoint.OwnedRecordLabelKey: "owned.foo.co"}),
		newEndpointWithOwnerAndLabels("pre-owned.foo.co", "xxx", endpoint.RecordTypeTXT, "owner",
			endpoint.Labels{endpoint.OwnedRecordLabelKey: "owned.foo.co"}),
	}
	source := []*endpoint.Endpoint{
		newEndpointWithOwner("old-not-owned.foo.co", "new-foo.loadbalancer.com", endpoint.RecordTypeA, "owner"),
		newEndpointWithOwner("not-owned.foo.co", "new-foo.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
		newEndpointWithOwner("old-owned.foo.co", "new-foo.loadbalancer.com", endpoint.RecordTypeA, "owner"),
		newEndpointWithOwner("owned.foo.co", "new-foo.loadbalancer.com", endpoint.RecordTypeA, "owner"),
	}

	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	r, _ := NewTXTRegistry(p, "pre-", "", "owner", time.Hour, "wc", nil, false, nil)
	source = r.EnsureOwnerShipRecords(source)
	fixedReg, fixedSource := r.RemoveUnownedRecords(registry, source)
	require.Len(t, fixedReg, 4)
	require.Len(t, fixedSource, 4)
}
