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

package registry

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/internal/testutils"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"sigs.k8s.io/external-dns/provider/inmemory"
)

const (
	testZone = "test-zone.example.org"
)

func TestTXTRegistry(t *testing.T) {
	t.Run("TestNewTXTRegistry", testTXTRegistryNew)
	t.Run("TestRecords", testTXTRegistryRecords)
	t.Run("TestApplyChanges", testTXTRegistryApplyChanges)
	t.Run("TestMissingRecords", testTXTRegistryMissingRecords)
}

func testTXTRegistryNew(t *testing.T) {
	p := inmemory.NewInMemoryProvider()
	_, err := NewTXTRegistry(p, "txt", "", "", time.Hour, "", []string{}, false, nil)
	require.Error(t, err)

	_, err = NewTXTRegistry(p, "", "txt", "", time.Hour, "", []string{}, false, nil)
	require.Error(t, err)

	r, err := NewTXTRegistry(p, "txt", "", "owner", time.Hour, "", []string{}, false, nil)
	require.NoError(t, err)
	assert.Equal(t, p, r.provider)

	r, err = NewTXTRegistry(p, "", "txt", "owner", time.Hour, "", []string{}, false, nil)
	require.NoError(t, err)

	_, err = NewTXTRegistry(p, "txt", "txt", "owner", time.Hour, "", []string{}, false, nil)
	require.Error(t, err)

	_, ok := r.mapper.(affixNameMapper)
	require.True(t, ok)
	assert.Equal(t, "owner", r.ownerID)
	assert.Equal(t, p, r.provider)

	aesKey := []byte(";k&l)nUC/33:{?d{3)54+,AD?]SX%yh^")
	_, err = NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, nil)
	require.NoError(t, err)

	_, err = NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, aesKey)
	require.NoError(t, err)

	_, err = NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, true, nil)
	require.Error(t, err)

	r, err = NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, true, aesKey)
	require.NoError(t, err)

	_, ok = r.mapper.(affixNameMapper)
	assert.True(t, ok)
}

func testTXTRegistryRecords(t *testing.T) {
	t.Run("With prefix", testTXTRegistryRecordsPrefixed)
	t.Run("With suffix", testTXTRegistryRecordsSuffixed)
	t.Run("No prefix", testTXTRegistryRecordsNoPrefix)
}

func testTXTRegistryRecordsPrefixed(t *testing.T) {
	ctx := context.Background()
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerAndLabels("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, "", endpoint.Labels{"foo": "somefoo"}),
			newEndpointWithOwnerAndLabels("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, "", endpoint.Labels{"bar": "somebar"}),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwnerAndLabels("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "", endpoint.Labels{"tar": "sometar"}),
			newEndpointWithOwner("TxT.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner-2\"", endpoint.RecordTypeTXT, ""), // case-insensitive TXT prefix
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("*.wildcard.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.wc.wildcard.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("dualstack.test-zone.example.org", "1.1.1.1", endpoint.RecordTypeA, ""),
			newEndpointWithOwner("txt.dualstack.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("dualstack.test-zone.example.org", "2001:DB8::1", endpoint.RecordTypeAAAA, ""),
			newEndpointWithOwner("aaaa-txt.dualstack.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner-2\"", endpoint.RecordTypeTXT, ""),
		},
	})
	expectedRecords := []*endpoint.Endpoint{
		{
			Name:       endpoint.NewEndpointNameCommon("foo.test-zone.example.org"),
			Targets:    endpoint.Targets{"foo.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
				"foo":                  "somefoo",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("bar.test-zone.example.org"),
			Targets:    endpoint.Targets{"my-domain.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
				"bar":                  "somebar",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("txt.bar.test-zone.example.org"),
			Targets:    endpoint.Targets{"baz.test-zone.example.org"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("qux.test-zone.example.org"),
			Targets:    endpoint.Targets{"random"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("tar.test-zone.example.org"),
			Targets:    endpoint.Targets{"tar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner-2",
				"tar":                  "sometar",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("foobar.test-zone.example.org"),
			Targets:    endpoint.Targets{"foobar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:          endpoint.NewEndpointNameCommon("multiple.test-zone.example.org"),
			Targets:       endpoint.Targets{"lb1.loadbalancer.com"},
			SetIdentifier: "test-set-1",
			RecordType:    endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:          endpoint.NewEndpointNameCommon("multiple.test-zone.example.org"),
			Targets:       endpoint.Targets{"lb2.loadbalancer.com"},
			SetIdentifier: "test-set-2",
			RecordType:    endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("*.wildcard.test-zone.example.org"),
			Targets:    endpoint.Targets{"foo.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("dualstack.test-zone.example.org"),
			Targets:    endpoint.Targets{"1.1.1.1"},
			RecordType: endpoint.RecordTypeA,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("dualstack.test-zone.example.org"),
			Targets:    endpoint.Targets{"2001:DB8::1"},
			RecordType: endpoint.RecordTypeAAAA,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner-2",
			},
		},
	}

	r, _ := NewTXTRegistry(p, "txt.", "", "owner", time.Hour, "wc", []string{}, false, nil)
	records, _ := r.Records(ctx)

	assert.True(t, testutils.SameEndpoints(records, expectedRecords))

	// Ensure prefix is case-insensitive
	r, _ = NewTXTRegistry(p, "TxT.", "", "owner", time.Hour, "", []string{}, false, nil)
	records, _ = r.Records(ctx)

	assert.True(t, testutils.SameEndpointLabels(records, expectedRecords))
}

func testTXTRegistryRecordsSuffixed(t *testing.T) {
	ctx := context.Background()
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerAndLabels("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, "", endpoint.Labels{"foo": "somefoo"}),
			newEndpointWithOwnerAndLabels("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, "", endpoint.Labels{"bar": "somebar"}),
			newEndpointWithOwner("bar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("bar-txt.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwnerAndLabels("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "", endpoint.Labels{"tar": "sometar"}),
			newEndpointWithOwner("tar-TxT.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner-2\"", endpoint.RecordTypeTXT, ""), // case-insensitive TXT prefix
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("dualstack.test-zone.example.org", "1.1.1.1", endpoint.RecordTypeA, ""),
			newEndpointWithOwner("dualstack-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("dualstack.test-zone.example.org", "2001:DB8::1", endpoint.RecordTypeAAAA, ""),
			newEndpointWithOwner("aaaa-dualstack-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner-2\"", endpoint.RecordTypeTXT, ""),
		},
	})
	expectedRecords := []*endpoint.Endpoint{
		{
			Name:       endpoint.NewEndpointNameCommon("foo.test-zone.example.org"),
			Targets:    endpoint.Targets{"foo.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
				"foo":                  "somefoo",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("bar.test-zone.example.org"),
			Targets:    endpoint.Targets{"my-domain.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
				"bar":                  "somebar",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("bar-txt.test-zone.example.org"),
			Targets:    endpoint.Targets{"baz.test-zone.example.org"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("qux.test-zone.example.org"),
			Targets:    endpoint.Targets{"random"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("tar.test-zone.example.org"),
			Targets:    endpoint.Targets{"tar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner-2",
				"tar":                  "sometar",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("foobar.test-zone.example.org"),
			Targets:    endpoint.Targets{"foobar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:          endpoint.NewEndpointNameCommon("multiple.test-zone.example.org"),
			Targets:       endpoint.Targets{"lb1.loadbalancer.com"},
			SetIdentifier: "test-set-1",
			RecordType:    endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:          endpoint.NewEndpointNameCommon("multiple.test-zone.example.org"),
			Targets:       endpoint.Targets{"lb2.loadbalancer.com"},
			SetIdentifier: "test-set-2",
			RecordType:    endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("dualstack.test-zone.example.org"),
			Targets:    endpoint.Targets{"1.1.1.1"},
			RecordType: endpoint.RecordTypeA,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("dualstack.test-zone.example.org"),
			Targets:    endpoint.Targets{"2001:DB8::1"},
			RecordType: endpoint.RecordTypeAAAA,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner-2",
			},
		},
	}

	r, _ := NewTXTRegistry(p, "", "-txt", "owner", time.Hour, "", []string{}, false, nil)
	records, _ := r.Records(ctx)

	assert.True(t, testutils.SameEndpoints(records, expectedRecords))

	// Ensure prefix is case-insensitive
	r, _ = NewTXTRegistry(p, "", "-TxT", "owner", time.Hour, "", []string{}, false, nil)
	records, _ = r.Records(ctx)

	assert.True(t, testutils.SameEndpointLabels(records, expectedRecords))
}

func testTXTRegistryRecordsNoPrefix(t *testing.T) {
	p := inmemory.NewInMemoryProvider()
	ctx := context.Background()
	p.CreateZone(testZone)
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner-2\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("dualstack.test-zone.example.org", "1.1.1.1", endpoint.RecordTypeA, ""),
			newEndpointWithOwner("dualstack.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("dualstack.test-zone.example.org", "2001:DB8::1", endpoint.RecordTypeAAAA, ""),
			newEndpointWithOwner("aaaa-dualstack.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner-2\"", endpoint.RecordTypeTXT, ""),
		},
	})
	expectedRecords := []*endpoint.Endpoint{
		{
			Name:       endpoint.NewEndpointNameCommon("foo.test-zone.example.org"),
			Targets:    endpoint.Targets{"foo.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("bar.test-zone.example.org"),
			Targets:    endpoint.Targets{"my-domain.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("txt.bar.test-zone.example.org"),
			Targets:    endpoint.Targets{"baz.test-zone.example.org"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey:    "owner",
				endpoint.ResourceLabelKey: "ingress/default/my-ingress",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("qux.test-zone.example.org"),
			Targets:    endpoint.Targets{"random"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("tar.test-zone.example.org"),
			Targets:    endpoint.Targets{"tar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("foobar.test-zone.example.org"),
			Targets:    endpoint.Targets{"foobar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("dualstack.test-zone.example.org"),
			Targets:    endpoint.Targets{"1.1.1.1"},
			RecordType: endpoint.RecordTypeA,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("dualstack.test-zone.example.org"),
			Targets:    endpoint.Targets{"2001:DB8::1"},
			RecordType: endpoint.RecordTypeAAAA,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner-2",
			},
		},
	}

	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, nil)
	records, _ := r.Records(ctx)

	assert.True(t, testutils.SameEndpoints(records, expectedRecords))
}

func testTXTRegistryApplyChanges(t *testing.T) {
	t.Run("With Prefix", testTXTRegistryApplyChangesWithPrefix)
	t.Run("With Templated Prefix", testTXTRegistryApplyChangesWithTemplatedPrefix)
	t.Run("With Templated Suffix", testTXTRegistryApplyChangesWithTemplatedSuffix)
	t.Run("With Suffix", testTXTRegistryApplyChangesWithSuffix)
	t.Run("No prefix", testTXTRegistryApplyChangesNoPrefix)
}

func testTXTRegistryApplyChangesWithPrefix(t *testing.T) {
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	ctxEndpoints := []*endpoint.Endpoint{}
	ctx := context.WithValue(context.Background(), provider.RecordsContextKey, ctxEndpoints)
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		assert.Equal(t, ctxEndpoints, ctx.Value(provider.RecordsContextKey))
	}
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.cname-tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.cname-foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("txt.cname-multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("txt.cname-multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-2"),
		},
	})
	r, _ := NewTXTRegistry(p, "txt.", "", "owner", time.Hour, "", []string{}, false, nil)

	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "", "ingress/default/my-ingress"),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "lb3.loadbalancer.com", endpoint.RecordTypeCNAME, "", "ingress/default/my-ingress").WithSetIdentifier("test-set-3"),
			newEndpointWithOwnerResource("example", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "", "ingress/default/my-ingress"),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-1"),
		},
		UpdateNew: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("tar.test-zone.example.org", "new-tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2"),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "new.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2").WithSetIdentifier("test-set-2"),
		},
		UpdateOld: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-2"),
		},
	}
	expected := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress"),
			newEndpointWithOwnerAndOwnedRecord("txt.new-record-1.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("txt.cname-new-record-1.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "lb3.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress").WithSetIdentifier("test-set-3"),
			newEndpointWithOwnerAndOwnedRecord("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-3"),
			newEndpointWithOwnerAndOwnedRecord("txt.cname-multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-3"),
			newEndpointWithOwnerResource("example", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress"),
			newEndpointWithOwnerAndOwnedRecord("txt.example", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "example"),
			newEndpointWithOwnerAndOwnedRecord("txt.cname-example", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "example"),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwnerAndOwnedRecord("txt.foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "foobar.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("txt.cname-foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "foobar.test-zone.example.org"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-1"),
			newEndpointWithOwnerAndOwnedRecord("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-1"),
			newEndpointWithOwnerAndOwnedRecord("txt.cname-multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-1"),
		},
		UpdateNew: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("tar.test-zone.example.org", "new-tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2"),
			newEndpointWithOwnerAndOwnedRecord("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress-2\"", endpoint.RecordTypeTXT, "", "tar.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("txt.cname-tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress-2\"", endpoint.RecordTypeTXT, "", "tar.test-zone.example.org"),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "new.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2").WithSetIdentifier("test-set-2"),
			newEndpointWithOwnerAndOwnedRecord("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress-2\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-2"),
			newEndpointWithOwnerAndOwnedRecord("txt.cname-multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress-2\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-2"),
		},
		UpdateOld: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwnerAndOwnedRecord("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "tar.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("txt.cname-tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "tar.test-zone.example.org"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-2"),
			newEndpointWithOwnerAndOwnedRecord("txt.multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-2"),
			newEndpointWithOwnerAndOwnedRecord("txt.cname-multiple.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-2"),
		},
	}
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		mExpected := map[string][]*endpoint.Endpoint{
			"Create":    expected.Create,
			"UpdateNew": expected.UpdateNew,
			"UpdateOld": expected.UpdateOld,
			"Delete":    expected.Delete,
		}
		mGot := map[string][]*endpoint.Endpoint{
			"Create":    got.Create,
			"UpdateNew": got.UpdateNew,
			"UpdateOld": got.UpdateOld,
			"Delete":    got.Delete,
		}
		assert.True(t, testutils.SamePlanChanges(mGot, mExpected))
		assert.Equal(t, nil, ctx.Value(provider.RecordsContextKey))
	}
	err := r.ApplyChanges(ctx, changes)
	require.NoError(t, err)
}

func testTXTRegistryApplyChangesWithTemplatedPrefix(t *testing.T) {
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	ctxEndpoints := []*endpoint.Endpoint{}
	ctx := context.WithValue(context.Background(), provider.RecordsContextKey, ctxEndpoints)
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		assert.Equal(t, ctxEndpoints, ctx.Value(provider.RecordsContextKey))
	}
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{},
	})
	r, _ := NewTXTRegistry(p, "prefix%{record_type}.", "", "owner", time.Hour, "", []string{}, false, nil)
	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "", "ingress/default/my-ingress"),
		},
		Delete:    []*endpoint.Endpoint{},
		UpdateOld: []*endpoint.Endpoint{},
		UpdateNew: []*endpoint.Endpoint{},
	}
	expected := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress"),
			newEndpointWithOwnerAndOwnedRecord("prefix.new-record-1.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("prefixcname.new-record-1.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
		},
	}
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		mExpected := map[string][]*endpoint.Endpoint{
			"Create":    expected.Create,
			"UpdateNew": expected.UpdateNew,
			"UpdateOld": expected.UpdateOld,
			"Delete":    expected.Delete,
		}
		mGot := map[string][]*endpoint.Endpoint{
			"Create":    got.Create,
			"UpdateNew": got.UpdateNew,
			"UpdateOld": got.UpdateOld,
			"Delete":    got.Delete,
		}
		assert.True(t, testutils.SamePlanChanges(mGot, mExpected))
		assert.Equal(t, nil, ctx.Value(provider.RecordsContextKey))
	}
	err := r.ApplyChanges(ctx, changes)
	require.NoError(t, err)
}

func testTXTRegistryApplyChangesWithTemplatedSuffix(t *testing.T) {
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	ctxEndpoints := []*endpoint.Endpoint{}
	ctx := context.WithValue(context.Background(), provider.RecordsContextKey, ctxEndpoints)
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		assert.Equal(t, ctxEndpoints, ctx.Value(provider.RecordsContextKey))
	}
	r, _ := NewTXTRegistry(p, "", "-%{record_type}suffix", "owner", time.Hour, "", []string{}, false, nil)
	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "", "ingress/default/my-ingress"),
		},
		Delete:    []*endpoint.Endpoint{},
		UpdateOld: []*endpoint.Endpoint{},
		UpdateNew: []*endpoint.Endpoint{},
	}
	expected := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress"),
			newEndpointWithOwnerAndOwnedRecord("new-record-1-cnamesuffix.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("new-record-1-suffix.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
		},
	}
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		mExpected := map[string][]*endpoint.Endpoint{
			"Create":    expected.Create,
			"UpdateNew": expected.UpdateNew,
			"UpdateOld": expected.UpdateOld,
			"Delete":    expected.Delete,
		}
		mGot := map[string][]*endpoint.Endpoint{
			"Create":    got.Create,
			"UpdateNew": got.UpdateNew,
			"UpdateOld": got.UpdateOld,
			"Delete":    got.Delete,
		}
		assert.True(t, testutils.SamePlanChanges(mGot, mExpected))
		assert.Equal(t, nil, ctx.Value(provider.RecordsContextKey))
	}
	err := r.ApplyChanges(ctx, changes)
	require.NoError(t, err)
}

func testTXTRegistryApplyChangesWithSuffix(t *testing.T) {
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	ctxEndpoints := []*endpoint.Endpoint{}
	ctx := context.WithValue(context.Background(), provider.RecordsContextKey, ctxEndpoints)
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		assert.Equal(t, ctxEndpoints, ctx.Value(provider.RecordsContextKey))
	}
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("bar-txt.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("bar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("cname-bar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("tar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("cname-tar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("foobar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("cname-foobar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("cname-multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-1"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-2"),
			newEndpointWithOwner("cname-multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "").WithSetIdentifier("test-set-2"),
		},
	})
	r, _ := NewTXTRegistry(p, "", "-txt", "owner", time.Hour, "wildcard", []string{}, false, nil)

	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "", "ingress/default/my-ingress"),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "lb3.loadbalancer.com", endpoint.RecordTypeCNAME, "", "ingress/default/my-ingress").WithSetIdentifier("test-set-3"),
			newEndpointWithOwnerResource("example", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "", "ingress/default/my-ingress"),
			newEndpointWithOwnerResource("*.wildcard.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "", "ingress/default/my-ingress"),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-1"),
		},
		UpdateNew: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("tar.test-zone.example.org", "new-tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2"),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "new.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2").WithSetIdentifier("test-set-2"),
		},
		UpdateOld: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-2"),
		},
	}
	expected := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress"),
			newEndpointWithOwnerAndOwnedRecord("new-record-1-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("cname-new-record-1-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "lb3.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress").WithSetIdentifier("test-set-3"),
			newEndpointWithOwnerAndOwnedRecord("multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-3"),
			newEndpointWithOwnerAndOwnedRecord("cname-multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-3"),
			newEndpointWithOwnerResource("example", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress"),
			newEndpointWithOwnerAndOwnedRecord("example-txt", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "example"),
			newEndpointWithOwnerAndOwnedRecord("cname-example-txt", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "example"),
			newEndpointWithOwnerResource("*.wildcard.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress"),
			newEndpointWithOwnerAndOwnedRecord("wildcard-txt.wildcard.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "*.wildcard.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("cname-wildcard-txt.wildcard.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress\"", endpoint.RecordTypeTXT, "", "*.wildcard.test-zone.example.org"),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwnerAndOwnedRecord("foobar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "foobar.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("cname-foobar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "foobar.test-zone.example.org"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb1.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-1"),
			newEndpointWithOwnerAndOwnedRecord("multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-1"),
			newEndpointWithOwnerAndOwnedRecord("cname-multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-1"),
		},
		UpdateNew: []*endpoint.Endpoint{
			newEndpointWithOwnerResource("tar.test-zone.example.org", "new-tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2"),
			newEndpointWithOwnerAndOwnedRecord("tar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress-2\"", endpoint.RecordTypeTXT, "", "tar.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("cname-tar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress-2\"", endpoint.RecordTypeTXT, "", "tar.test-zone.example.org"),
			newEndpointWithOwnerResource("multiple.test-zone.example.org", "new.loadbalancer.com", endpoint.RecordTypeCNAME, "owner", "ingress/default/my-ingress-2").WithSetIdentifier("test-set-2"),
			newEndpointWithOwnerAndOwnedRecord("multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress-2\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-2"),
			newEndpointWithOwnerAndOwnedRecord("cname-multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner,external-dns/resource=ingress/default/my-ingress-2\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-2"),
		},
		UpdateOld: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwnerAndOwnedRecord("tar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "tar.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("cname-tar-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "tar.test-zone.example.org"),
			newEndpointWithOwner("multiple.test-zone.example.org", "lb2.loadbalancer.com", endpoint.RecordTypeCNAME, "owner").WithSetIdentifier("test-set-2"),
			newEndpointWithOwnerAndOwnedRecord("multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-2"),
			newEndpointWithOwnerAndOwnedRecord("cname-multiple-txt.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "multiple.test-zone.example.org").WithSetIdentifier("test-set-2"),
		},
	}
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		mExpected := map[string][]*endpoint.Endpoint{
			"Create":    expected.Create,
			"UpdateNew": expected.UpdateNew,
			"UpdateOld": expected.UpdateOld,
			"Delete":    expected.Delete,
		}
		mGot := map[string][]*endpoint.Endpoint{
			"Create":    got.Create,
			"UpdateNew": got.UpdateNew,
			"UpdateOld": got.UpdateOld,
			"Delete":    got.Delete,
		}
		assert.True(t, testutils.SamePlanChanges(mGot, mExpected))
		assert.Equal(t, nil, ctx.Value(provider.RecordsContextKey))
	}
	err := r.ApplyChanges(ctx, changes)
	require.NoError(t, err)
}

func testTXTRegistryApplyChangesNoPrefix(t *testing.T) {
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	ctxEndpoints := []*endpoint.Endpoint{}
	ctx := context.WithValue(context.Background(), provider.RecordsContextKey, ctxEndpoints)
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		assert.Equal(t, ctxEndpoints, ctx.Value(provider.RecordsContextKey))
	}
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("cname-foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
		},
	})
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, nil)

	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("example", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, ""),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
		},
		UpdateNew: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "new-tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner-2"),
		},
		UpdateOld: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner-2"),
		},
	}
	expected := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwnerAndOwnedRecord("new-record-1.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("cname-new-record-1.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
			newEndpointWithOwner("example", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwnerAndOwnedRecord("example", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "example"),
			newEndpointWithOwnerAndOwnedRecord("cname-example", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "example"),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwnerAndOwnedRecord("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "foobar.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("cname-foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "foobar.test-zone.example.org"),
		},
		UpdateNew: []*endpoint.Endpoint{},
		UpdateOld: []*endpoint.Endpoint{},
	}
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		mExpected := map[string][]*endpoint.Endpoint{
			"Create":    expected.Create,
			"UpdateNew": expected.UpdateNew,
			"UpdateOld": expected.UpdateOld,
			"Delete":    expected.Delete,
		}
		mGot := map[string][]*endpoint.Endpoint{
			"Create":    got.Create,
			"UpdateNew": got.UpdateNew,
			"UpdateOld": got.UpdateOld,
			"Delete":    got.Delete,
		}
		assert.True(t, testutils.SamePlanChanges(mGot, mExpected))
		assert.Equal(t, nil, ctx.Value(provider.RecordsContextKey))
	}
	err := r.ApplyChanges(ctx, changes)
	require.NoError(t, err)
}

func testTXTRegistryMissingRecords(t *testing.T) {
	t.Run("No prefix", testTXTRegistryMissingRecordsNoPrefix)
	t.Run("With Prefix", testTXTRegistryMissingRecordsWithPrefix)
}

func testTXTRegistryMissingRecordsNoPrefix(t *testing.T) {
	ctx := context.Background()
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("oldformat.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("oldformat.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("oldformat2.test-zone.example.org", "bar.loadbalancer.com", endpoint.RecordTypeA, ""),
			newEndpointWithOwner("oldformat2.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("newformat.test-zone.example.org", "foobar.nameserver.com", endpoint.RecordTypeNS, ""),
			newEndpointWithOwner("ns-newformat.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("newformat.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("noheritage.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("oldformat-otherowner.test-zone.example.org", "bar.loadbalancer.com", endpoint.RecordTypeA, ""),
			newEndpointWithOwner("oldformat-otherowner.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=otherowner\"", endpoint.RecordTypeTXT, ""),
			endpoint.NewEndpoint("unmanaged1.test-zone.example.org", endpoint.RecordTypeA, "unmanaged1.loadbalancer.com"),
			endpoint.NewEndpoint("unmanaged2.test-zone.example.org", endpoint.RecordTypeCNAME, "unmanaged2.loadbalancer.com"),
			newEndpointWithOwner("this-is-a-63-characters-long-label-that-we-do-expect-will-work.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("this-is-a-63-characters-long-label-that-we-do-expect-will-work.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
		},
	})
	expectedRecords := []*endpoint.Endpoint{
		{
			Name:       endpoint.NewEndpointNameCommon("oldformat.test-zone.example.org"),
			Targets:    endpoint.Targets{"foo.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				// owner was added from the TXT record's target
				endpoint.OwnerLabelKey: "owner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("oldformat2.test-zone.example.org"),
			Targets:    endpoint.Targets{"bar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeA,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("newformat.test-zone.example.org"),
			Targets:    endpoint.Targets{"foobar.nameserver.com"},
			RecordType: endpoint.RecordTypeNS,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
		// Only TXT records with the wrong heritage are returned by Records()
		{
			Name:       endpoint.NewEndpointNameCommon("noheritage.test-zone.example.org"),
			Targets:    endpoint.Targets{"random"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				// No owner because it's not external-dns heritage
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("oldformat-otherowner.test-zone.example.org"),
			Targets:    endpoint.Targets{"bar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeA,
			Labels: map[string]string{
				// Records() retrieves all the records of the zone, no matter the owner
				endpoint.OwnerLabelKey: "otherowner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("unmanaged1.test-zone.example.org"),
			Targets:    endpoint.Targets{"unmanaged1.loadbalancer.com"},
			RecordType: endpoint.RecordTypeA,
		},
		{
			Name:       endpoint.NewEndpointNameCommon("unmanaged2.test-zone.example.org"),
			Targets:    endpoint.Targets{"unmanaged2.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
		},
		{
			Name:       endpoint.NewEndpointNameCommon("this-is-a-63-characters-long-label-that-we-do-expect-will-work.test-zone.example.org"),
			Targets:    endpoint.Targets{"foo.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
	}

	// expectedMissingRecords := []*endpoint.Endpoint{
	// 	{
	// 		Name: endpoint.NewEndpointNameCommon("cname-oldformat.test-zone.example.org"),
	// 		// owner is taken from the source record (A, CNAME, etc.)
	// 		Targets:    endpoint.Targets{"\"heritage=external-dns,external-dns/owner=owner\""},
	// 		RecordType: endpoint.RecordTypeTXT,
	// 		Labels: endpoint.Labels{
	// 			endpoint.OwnedRecordLabelKey: "oldformat.test-zone.example.org",
	// 		},
	// 	},
	// 	{
	// 		Name: endpoint.NewEndpointNameCommon("a-oldformat2.test-zone.example.org"),
	// 		Targets:    endpoint.Targets{"\"heritage=external-dns,external-dns/owner=owner\""},
	// 		RecordType: endpoint.RecordTypeTXT,
	// 		Labels: endpoint.Labels{
	// 			endpoint.OwnedRecordLabelKey: "oldformat2.test-zone.example.org",
	// 		},
	// 	},
	// }

	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "wc", []string{endpoint.RecordTypeCNAME, endpoint.RecordTypeA, endpoint.RecordTypeNS}, false, nil)
	records, _ := r.Records(ctx)
	// missingRecords := r.MissingRecords()

	assert.True(t, testutils.SameEndpoints(records, expectedRecords))
	// assert.True(t, testutils.SameEndpoints(missingRecords, expectedMissingRecords))
}

func testTXTRegistryMissingRecordsWithPrefix(t *testing.T) {
	ctx := context.Background()
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("oldformat.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.oldformat.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("oldformat2.test-zone.example.org", "bar.loadbalancer.com", endpoint.RecordTypeA, ""),
			newEndpointWithOwner("txt.oldformat2.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("newformat.test-zone.example.org", "foobar.nameserver.com", endpoint.RecordTypeNS, ""),
			newEndpointWithOwner("txt.ns-newformat.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.newformat.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("noheritage.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("oldformat-otherowner.test-zone.example.org", "bar.loadbalancer.com", endpoint.RecordTypeA, ""),
			newEndpointWithOwner("txt.oldformat-otherowner.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=otherowner\"", endpoint.RecordTypeTXT, ""),
			endpoint.NewEndpoint("unmanaged1.test-zone.example.org", endpoint.RecordTypeA, "unmanaged1.loadbalancer.com"),
			endpoint.NewEndpoint("unmanaged2.test-zone.example.org", endpoint.RecordTypeCNAME, "unmanaged2.loadbalancer.com"),
		},
	})
	expectedRecords := []*endpoint.Endpoint{
		{
			Name:       endpoint.NewEndpointNameCommon("oldformat.test-zone.example.org"),
			Targets:    endpoint.Targets{"foo.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
			Labels: map[string]string{
				// owner was added from the TXT record's target
				endpoint.OwnerLabelKey: "owner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("oldformat2.test-zone.example.org"),
			Targets:    endpoint.Targets{"bar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeA,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("newformat.test-zone.example.org"),
			Targets:    endpoint.Targets{"foobar.nameserver.com"},
			RecordType: endpoint.RecordTypeNS,
			Labels: map[string]string{
				endpoint.OwnerLabelKey: "owner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("noheritage.test-zone.example.org"),
			Targets:    endpoint.Targets{"random"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				// No owner because it's not external-dns heritage
				endpoint.OwnerLabelKey: "",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("oldformat-otherowner.test-zone.example.org"),
			Targets:    endpoint.Targets{"bar.loadbalancer.com"},
			RecordType: endpoint.RecordTypeA,
			Labels: map[string]string{
				// All the records of the zone are retrieved, no matter the owner
				endpoint.OwnerLabelKey: "otherowner",
			},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("unmanaged1.test-zone.example.org"),
			Targets:    endpoint.Targets{"unmanaged1.loadbalancer.com"},
			RecordType: endpoint.RecordTypeA,
		},
		{
			Name:       endpoint.NewEndpointNameCommon("unmanaged2.test-zone.example.org"),
			Targets:    endpoint.Targets{"unmanaged2.loadbalancer.com"},
			RecordType: endpoint.RecordTypeCNAME,
		},
	}

	// expectedMissingRecords := []*endpoint.Endpoint{
	// 	{
	// 		Name: endpoint.NewEndpointNameCommon("txt.cname-oldformat.test-zone.example.org"),
	// 		// owner is taken from the source record (A, CNAME, etc.)
	// 		Targets:    endpoint.Targets{"\"heritage=external-dns,external-dns/owner=owner\""},
	// 		RecordType: endpoint.RecordTypeTXT,
	// 		Labels: endpoint.Labels{
	// 			endpoint.OwnedRecordLabelKey: "oldformat.test-zone.example.org",
	// 		},
	// 	},
	// 	{
	// 		Name: endpoint.NewEndpointNameCommon("txt.a-oldformat2.test-zone.example.org"),
	// 		Targets:    endpoint.Targets{"\"heritage=external-dns,external-dns/owner=owner\""},
	// 		RecordType: endpoint.RecordTypeTXT,
	// 		Labels: endpoint.Labels{
	// 			endpoint.OwnedRecordLabelKey: "oldformat2.test-zone.example.org",
	// 		},
	// 	},
	// }

	r, _ := NewTXTRegistry(p, "txt.", "", "owner", time.Hour, "wc", []string{endpoint.RecordTypeCNAME, endpoint.RecordTypeA, endpoint.RecordTypeNS}, false, nil)
	records, _ := r.Records(ctx)
	// missingRecords := r.MissingRecords()

	assert.True(t, testutils.SameEndpoints(records, expectedRecords))
	// assert.True(t, testutils.SameEndpoints(missingRecords, expectedMissingRecords))
}

func TestCacheMethods(t *testing.T) {
	cache := []*endpoint.Endpoint{
		newEndpointWithOwner("thing.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing1.com", "1.2.3.6", "A", "owner"),
		newEndpointWithOwner("thing2.com", "1.2.3.4", "CNAME", "owner"),
		newEndpointWithOwner("thing3.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing4.com", "1.2.3.4", "A", "owner"),
	}
	registry := &TXTRegistry{
		recordsCache:  cache,
		cacheInterval: time.Hour,
	}

	expectedCacheAfterAdd := []*endpoint.Endpoint{
		newEndpointWithOwner("thing.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing1.com", "1.2.3.6", "A", "owner"),
		newEndpointWithOwner("thing2.com", "1.2.3.4", "CNAME", "owner"),
		newEndpointWithOwner("thing3.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing4.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing4.com", "2001:DB8::1", "AAAA", "owner"),
		newEndpointWithOwner("thing5.com", "1.2.3.5", "A", "owner"),
	}

	expectedCacheAfterUpdate := []*endpoint.Endpoint{
		newEndpointWithOwner("thing1.com", "1.2.3.6", "A", "owner"),
		newEndpointWithOwner("thing2.com", "1.2.3.4", "CNAME", "owner"),
		newEndpointWithOwner("thing3.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing4.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing5.com", "1.2.3.5", "A", "owner"),
		newEndpointWithOwner("thing.com", "1.2.3.6", "A", "owner2"),
		newEndpointWithOwner("thing4.com", "2001:DB8::2", "AAAA", "owner"),
	}

	expectedCacheAfterDelete := []*endpoint.Endpoint{
		newEndpointWithOwner("thing1.com", "1.2.3.6", "A", "owner"),
		newEndpointWithOwner("thing2.com", "1.2.3.4", "CNAME", "owner"),
		newEndpointWithOwner("thing3.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing4.com", "1.2.3.4", "A", "owner"),
		newEndpointWithOwner("thing5.com", "1.2.3.5", "A", "owner"),
	}
	// test add cache
	registry.addToCache(newEndpointWithOwner("thing4.com", "2001:DB8::1", "AAAA", "owner"))
	registry.addToCache(newEndpointWithOwner("thing5.com", "1.2.3.5", "A", "owner"))

	if !reflect.DeepEqual(expectedCacheAfterAdd, registry.recordsCache) {
		t.Fatalf("expected endpoints should match endpoints from cache: expected %v, but got %v", expectedCacheAfterAdd, registry.recordsCache)
	}

	// test update cache
	registry.removeFromCache(newEndpointWithOwner("thing.com", "1.2.3.4", "A", "owner"))
	registry.addToCache(newEndpointWithOwner("thing.com", "1.2.3.6", "A", "owner2"))
	registry.removeFromCache(newEndpointWithOwner("thing4.com", "2001:DB8::1", "AAAA", "owner"))
	registry.addToCache(newEndpointWithOwner("thing4.com", "2001:DB8::2", "AAAA", "owner"))
	// ensure it was updated
	if !reflect.DeepEqual(expectedCacheAfterUpdate, registry.recordsCache) {
		t.Fatalf("expected endpoints should match endpoints from cache: expected %v, but got %v", expectedCacheAfterUpdate, registry.recordsCache)
	}

	// test deleting a record
	registry.removeFromCache(newEndpointWithOwner("thing.com", "1.2.3.6", "A", "owner2"))
	registry.removeFromCache(newEndpointWithOwner("thing4.com", "2001:DB8::2", "AAAA", "owner"))
	// ensure it was deleted
	if !reflect.DeepEqual(expectedCacheAfterDelete, registry.recordsCache) {
		t.Fatalf("expected endpoints should match endpoints from cache: expected %v, but got %v", expectedCacheAfterDelete, registry.recordsCache)
	}
}

// func TestDropPrefix(t *testing.T) {
// 	mapper := newaffixNameMapper("foo-%{record_type}-", "", "")
// 	cnameRecord := "foo-cname-test.example.com"
// 	aRecord := "foo-a-test.example.com"
// 	expectedCnameRecord := "test.example.com"
// 	expectedARecord := "test.example.com"
// 	actualCnameRecord := mapper.dropAffix(cnameRecord)
// 	actualARecord := mapper.dropAffix(aRecord)
// 	assert.Equal(t, expectedCnameRecord, actualCnameRecord)
// 	assert.Equal(t, expectedARecord, actualARecord)
// }

// func TestDropSuffix(t *testing.T) {
// 	mapper := newaffixNameMapper("", "-%{record_type}-foo", "")
// 	aRecord := "test-a-foo.example.com"
// 	expectedARecord := "test.example.com"
// 	r := strings.SplitN(aRecord, ".", 2)
// 	actualARecord := mapper.dropAffix(r[0]) + "." + r[1]
// 	assert.Equal(t, expectedARecord, actualARecord)
// }

func TestExtractRecordType(t *testing.T) {
	tests := []struct {
		input        string
		expectedName string
		expectedType string
	}{
		{
			input:        "ns-zone.example.com",
			expectedName: "zone.example.com",
			expectedType: "NS",
		},
		{
			input:        "aaaa-zone.example.com",
			expectedName: "zone.example.com",
			expectedType: "AAAA",
		},
		{
			input:        "PtR-zone.example.com",
			expectedName: "zone.example.com",
			expectedType: "PTR",
		},
		{
			input:        "coc-zone.example.com",
			expectedName: "coc-zone.example.com",
			expectedType: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			actualName, actualType := extractRecordType(tc.input)
			assert.Equal(t, tc.expectedName, actualName)
			assert.Equal(t, tc.expectedType, actualType)
		})
	}
}

func TestNewTXTScheme(t *testing.T) {
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	ctxEndpoints := []*endpoint.Endpoint{}
	ctx := context.WithValue(context.Background(), provider.RecordsContextKey, ctxEndpoints)
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		assert.Equal(t, ctxEndpoints, ctx.Value(provider.RecordsContextKey))
	}
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("foo.test-zone.example.org", "foo.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("bar.test-zone.example.org", "my-domain.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("txt.bar.test-zone.example.org", "baz.test-zone.example.org", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("qux.test-zone.example.org", "random", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("txt.tar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
			newEndpointWithOwner("cname-foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, ""),
		},
	})
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, nil)

	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, ""),
			newEndpointWithOwner("example", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, ""),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
		},
		UpdateNew: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "new-tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner-2"),
		},
		UpdateOld: []*endpoint.Endpoint{
			newEndpointWithOwner("tar.test-zone.example.org", "tar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner-2"),
		},
	}
	expected := &plan.Changes{
		Create: []*endpoint.Endpoint{
			newEndpointWithOwner("new-record-1.test-zone.example.org", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwnerAndOwnedRecord("new-record-1.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("cname-new-record-1.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "new-record-1.test-zone.example.org"),
			newEndpointWithOwner("example", "new-loadbalancer-1.lb.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwnerAndOwnedRecord("example", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "example"),
			newEndpointWithOwnerAndOwnedRecord("cname-example", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "example"),
		},
		Delete: []*endpoint.Endpoint{
			newEndpointWithOwner("foobar.test-zone.example.org", "foobar.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
			newEndpointWithOwnerAndOwnedRecord("foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "foobar.test-zone.example.org"),
			newEndpointWithOwnerAndOwnedRecord("cname-foobar.test-zone.example.org", "\"heritage=external-dns,external-dns/owner=owner\"", endpoint.RecordTypeTXT, "", "foobar.test-zone.example.org"),
		},
		UpdateNew: []*endpoint.Endpoint{},
		UpdateOld: []*endpoint.Endpoint{},
	}
	p.OnApplyChanges = func(ctx context.Context, got *plan.Changes) {
		mExpected := map[string][]*endpoint.Endpoint{
			"Create":    expected.Create,
			"UpdateNew": expected.UpdateNew,
			"UpdateOld": expected.UpdateOld,
			"Delete":    expected.Delete,
		}
		mGot := map[string][]*endpoint.Endpoint{
			"Create":    got.Create,
			"UpdateNew": got.UpdateNew,
			"UpdateOld": got.UpdateOld,
			"Delete":    got.Delete,
		}
		assert.True(t, testutils.SamePlanChanges(mGot, mExpected))
		assert.Equal(t, nil, ctx.Value(provider.RecordsContextKey))
	}
	err := r.ApplyChanges(ctx, changes)
	require.NoError(t, err)
}

func TestGenerateTXTForA(t *testing.T) {
	record := newEndpointWithOwner("foo.test-zone.example.org", "8.1.1.1", endpoint.RecordTypeA, "owner")
	expectedTXT := []*endpoint.Endpoint{
		{
			Name:       endpoint.NewEndpointNameCommon("a-foo.test-zone.example.org"),
			Targets:    endpoint.Targets{"heritage=external-dns,external-dns/owner=owner"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				endpoint.OwnedRecordLabelKey: "foo.test-zone.example.org",
			},
		},
	}
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, nil)
	gotTXT := r.generateTXTRecord(record)
	assert.Equal(t, expectedTXT, gotTXT)
}

func TestGenerateTXTForTXTHeritage(t *testing.T) {
	record := newEndpointWithOwner("foo.test-zone.example.org", "heritage=external-dns,external-dns/owner=XXX", endpoint.RecordTypeTXT, "owner")
	expectedTXT := []*endpoint.Endpoint{}
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, nil)
	gotTXT := r.generateTXTRecord(record)
	assert.Equal(t, expectedTXT, gotTXT)
}

func TestGenerateTXTForTXT(t *testing.T) {
	record := newEndpointWithOwner("foo.test-zone.example.org", "my-txt", endpoint.RecordTypeTXT, "owner")
	expectedTXT := []*endpoint.Endpoint{
		{
			Name:       endpoint.NewEndpointNameCommon("txt-foo.test-zone.example.org"),
			Targets:    endpoint.Targets{"heritage=external-dns,external-dns/owner=owner"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				endpoint.OwnedRecordLabelKey: "foo.test-zone.example.org",
			},
		},
	}
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, nil)
	gotTXT := r.generateTXTRecord(record)
	assert.Equal(t, expectedTXT, gotTXT)
}

func TestGenerateTXTForCNAME(t *testing.T) {
	record := newEndpointWithOwner("foo.test-zone.example.org", "new-foo.loadbalancer.com", endpoint.RecordTypeCNAME, "owner")
	expectedTXT := []*endpoint.Endpoint{
		{
			Name:       endpoint.NewEndpointNameCommon("cname-foo.test-zone.example.org"),
			Targets:    endpoint.Targets{"heritage=external-dns,external-dns/owner=owner"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				endpoint.OwnedRecordLabelKey: "foo.test-zone.example.org",
			},
		},
	}
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, nil)
	gotTXT := r.generateTXTRecord(record)
	assert.Equal(t, expectedTXT, gotTXT)
}

func TestGenerateTXTForAAAA(t *testing.T) {
	record := newEndpointWithOwner("foo.test-zone.example.org", "2001:DB8::1", endpoint.RecordTypeAAAA, "owner")
	expectedTXT := []*endpoint.Endpoint{
		{
			Name:       endpoint.NewEndpointNameCommon("aaaa-foo.test-zone.example.org"),
			Targets:    endpoint.Targets{"heritage=external-dns,external-dns/owner=owner"},
			RecordType: endpoint.RecordTypeTXT,
			Labels: map[string]string{
				endpoint.OwnedRecordLabelKey: "foo.test-zone.example.org",
			},
		},
	}
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, nil)
	gotTXT := r.generateTXTRecord(record)
	assert.Equal(t, expectedTXT, gotTXT)
}

func TestFailGenerateTXT(t *testing.T) {

	cnameRecord := &endpoint.Endpoint{
		Name:       endpoint.NewEndpointNameCommon("foo-some-really-big-name-not-supported-and-will-fail-000000000000000000.test-zone.example.org"),
		Targets:    endpoint.Targets{"new-foo.loadbalancer.com"},
		RecordType: endpoint.RecordTypeCNAME,
		Labels:     map[string]string{},
	}
	// A bad DNS name returns empty expected TXT
	expectedTXT := []*endpoint.Endpoint{}
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "", []string{}, false, nil)
	gotTXT := r.generateTXTRecord(cnameRecord)
	assert.Equal(t, expectedTXT, gotTXT)
}

func TestEnsureOwnerShipRecords(t *testing.T) {
	endpoints := []*endpoint.Endpoint{
		newEndpointWithOwner("foo.test-zone.example.org", "new-foo.loadbalancer.com", endpoint.RecordTypeCNAME, "owner"),
		newEndpointWithOwner("a-test.zone.bla", "new-foo.loadbalancer.com", endpoint.RecordTypeTXT, "owner2"),
		newEndpointWithOwner("*.zone.bla", "new-foo.loadbalancer.com", endpoint.RecordTypeMX, "owner3"),
		newEndpointWithOwner("txt.bar.test-zone.example.org", "heritage=external-dns,external-dns/owner=owner", endpoint.RecordTypeTXT, "yolo"),
	}
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	r, _ := NewTXTRegistry(p, "pre-", "", "owner", time.Hour, "wc", nil, false, nil)
	withHeritage := r.EnsureOwnerShipRecords(endpoints)
	require.Len(t, withHeritage, 7)
	for i, ep := range endpoints {
		if ep.RecordType != endpoint.RecordTypeTXT || !strings.HasPrefix(ep.Targets[0], "heritage=") {
			dnsName := ep.DNSName
			if strings.HasPrefix(dnsName, "*") {
				dnsName = "wc" + dnsName[1:]
			}
			ownerRec := newEndpointWithOwner(fmt.Sprintf("pre-%s-%s", strings.ToLower(ep.RecordType), dnsName),
				fmt.Sprintf("heritage=external-dns,external-dns/owner=%s", ep.Labels[endpoint.OwnerLabelKey]),
				endpoint.RecordTypeTXT, ep.Labels[endpoint.OwnerLabelKey])
			ownerRec.Labels[endpoint.OwnedRecordLabelKey] = ep.DNSName
			delete(ownerRec.Labels, endpoint.OwnerLabelKey)
			assert.Equal(t, ownerRec, withHeritage[i*2+1])
		}
	}
}

func TestRecordsLabelProcessingAmbiguousOldLabel(t *testing.T) {
	ctx := context.Background()
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			endpoint.NewEndpoint("no-owner-record.test.test-zone.example.org", endpoint.RecordTypeTXT,
				"heritage=external-dns,external-dns/owner=owner,external-dns/resource=wurst",
				"heritage=external-dns,external-dns/owner=xowner,external-dns/resource=wurst"),
		},
	})
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "wc", nil, false, nil)
	records, err := r.Records(ctx)
	require.NoError(t, err)
	require.Len(t, records, 2)
}

func TestRecordsLabelProcessingAmbiguousMixLabel(t *testing.T) {
	ctx := context.Background()
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			endpoint.NewEndpoint("no-owner-record.test.test-zone.example.org", endpoint.RecordTypeTXT,
				"heritage=external-dns,external-dns/owner=owner,external-dns/resource=wurst"),
			endpoint.NewEndpoint("a-no-owner-record.test.test-zone.example.org", endpoint.RecordTypeTXT,
				"heritage=external-dns,external-dns/owner=xowner,external-dns/resource=wurst"),
		},
	})
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "wc", nil, false, nil)
	records, err := r.Records(ctx)
	require.NoError(t, err)
	require.Len(t, records, 2)

}

func TestMapperDropAffix(t *testing.T) {
	oldrtypes := []string{endpoint.RecordTypeA, endpoint.RecordTypeCNAME}
	t.Run("no prefix + suffix", func(t *testing.T) {
		mapper := affixNameMapper{}
		res, rts := mapper.dropAffix("foo.test-zone.example.org")
		assert.Equal(t, "foo.test-zone.example.org", res)
		assert.Equal(t, oldrtypes, rts)

		res, rts = mapper.dropAffix("*.foo.test-zone.example.org")
		assert.Equal(t, "*.foo.test-zone.example.org", res)
		assert.Equal(t, oldrtypes, rts)

		for _, rt := range endpoint.AllRecordTypes {
			name := strings.ToLower(fmt.Sprintf("%sfoo.test-zone.example.org", rt))
			res, rts = mapper.dropAffix(name)
			assert.Equal(t, "foo.test-zone.example.org", res)
			assert.Equal(t, []string{rt}, rts)
		}
	})

	t.Run("prefix pre-", func(t *testing.T) {
		mapper := affixNameMapper{prefix: "pre-"}
		res, rts := mapper.dropAffix("foo.test-zone.example.org")
		assert.Equal(t, "", res)
		assert.Len(t, rts, 0)

		res, rts = mapper.dropAffix("pre-foo.test-zone.example.org")
		assert.Equal(t, "foo.test-zone.example.org", res)
		assert.Equal(t, oldrtypes, rts)

		for _, rt := range endpoint.AllRecordTypes {
			name := fmt.Sprintf("pre-%sfoo.test-zone.example.org", rt)
			res, rts = mapper.dropAffix(name)
			assert.Equal(t, "foo.test-zone.example.org", res)
			assert.Equal(t, []string{rt}, rts)
		}
	})

	t.Run("prefix template", func(t *testing.T) {
		mapper := affixNameMapper{prefix: "pre-%{record_type}."}
		res, rts := mapper.dropAffix("foo.test-zone.example.org")
		assert.Equal(t, "", res)
		assert.Len(t, rts, 0)

		res, rts = mapper.dropAffix("pre-.foo.test-zone.example.org")
		assert.Equal(t, "foo.test-zone.example.org", res)
		assert.Equal(t, oldrtypes, rts)

		for _, rt := range endpoint.AllRecordTypes {
			name := fmt.Sprintf("pre-%s.foo.test-zone.example.org", rt)
			res, rts = mapper.dropAffix(name)
			assert.Equal(t, "foo.test-zone.example.org", res)
			assert.Equal(t, []string{rt}, rts)
		}
	})

	t.Run("suffix", func(t *testing.T) {
		mapper := affixNameMapper{}
		res := mapper.dropAffix("moep.foo.test-zone.example.org")
		assert.Equal(t, "", res)

		res = mapper.dropAffix("moep.foo.test-zone.example.org")
		assert.Equal(t, "foo.test-zone.example.org", res)

		for _, rt := range endpoint.AllRecordTypes {
			name := fmt.Sprintf("foo-%s-suf.test-zone.example.org", rt)
			res = mapper.dropAffix(name)
			assert.Equal(t, fmt.Sprintf("foo-%s.test-zone.example.org", rt), res)
		}
	})

	t.Run("suffix -suf", func(t *testing.T) {
		mapper := affixNameMapper{suffix: "-suf"}
		res := mapper.dropAffix("foo.test-zone.example.org")
		assert.Equal(t, "", res)

		res = mapper.dropAffix("foo-suf.test-zone.example.org")
		assert.Equal(t, "foo.test-zone.example.org", res)

		for _, rt := range endpoint.AllRecordTypes {
			name := fmt.Sprintf("foo-%s-suf.test-zone.example.org", rt)
			res = mapper.dropAffix(name)
			assert.Equal(t, fmt.Sprintf("foo-%s.test-zone.example.org", rt), res)
		}
	})

	// t.Run("suffix template", func(t *testing.T) {
	// 	mapper := affixNameMapper{suffix: ".%{recordtype}-suf."}
	// 	res := mapper.dropAffix("foo.test-zone.example.org")
	// 	assert.Equal(t, "", res)

	// 	res = mapper.dropAffix("foo.-suf.test-zone.example.org")
	// 	assert.Equal(t, "foo.test-zone.example.org", res)

	// 	for _, rt := range endpoint.AllRecordTypes {
	// 		name := fmt.Sprintf("foo.%s-suf.test-zone.example.org", rt)
	// 		res = mapper.dropAffix(name)
	// 		assert.Equal(t, "foo.test-zone.example.org", res)
	// 	}
	// })

}
func TestMapperToEndpointName(t *testing.T) {

	p := inmemory.NewInMemoryProvider()
	oldrtypes := []string{endpoint.RecordTypeA, endpoint.RecordTypeCNAME}
	t.Run("no prefix + suffix", func(t *testing.T) {
		r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "wc", nil, false, nil)
		name, rt := r.mapper.toEndpointName("foo.test-zone.example.org")
		assert.Equal(t, "foo.test-zone.example.org", name)
		assert.Equal(t, oldrtypes, rt)
	})

	t.Run("prefix", func(t *testing.T) {
		r, _ := NewTXTRegistry(p, "pre-", "", "owner", time.Hour, "wc", nil, false, nil)
		name, rt := r.mapper.toEndpointName("foo.test-zone.example.org")
		assert.Equal(t, "foo.test-zone.example.org", name)
		assert.Equal(t, oldrtypes, rt)

		name, rt = r.mapper.toEndpointName("pre-pre-foo.test-zone.example.org")
		assert.Equal(t, "pre-foo.test-zone.example.org", name)
		assert.Equal(t, oldrtypes, rt)

		for _, rt := range endpoint.AllRecordTypes {
			name, rts := r.mapper.toEndpointName(fmt.Sprintf("pre-%s-foo.test-zone.example.org", rt))
			assert.Equal(t, "foo.test-zone.example.org", name)
			assert.Equal(t, []string{rt}, rts)
		}
	})

	t.Run("prefix-template", func(t *testing.T) {
		r, _ := NewTXTRegistry(p, "_%{record_type}.", "", "owner", time.Hour, "wc", nil, false, nil)
		name, rt := r.mapper.toEndpointName("foo.test-zone.example.org")
		assert.Equal(t, "foo.test-zone.example.org", name)
		assert.Equal(t, oldrtypes, rt)

		name, rt = r.mapper.toEndpointName("_foo.test-zone.example.org")
		assert.Equal(t, "_foo.test-zone.example.org", name)
		assert.Equal(t, oldrtypes, rt)

		name, rt = r.mapper.toEndpointName("_._pre-foo.test-zone.example.org")
		assert.Equal(t, "_pre-foo.test-zone.example.org", name)
		assert.Equal(t, oldrtypes, rt)

		for _, rt := range endpoint.AllRecordTypes {
			rt := strings.ToLower(rt)
			name, rts := r.mapper.toEndpointName(fmt.Sprintf("_%s.%s-foo.test-zone.example.org", rt, rt))
			assert.Equal(t, fmt.Sprintf("%s-foo.test-zone.example.org", rt), name)
			assert.Equal(t, []string{rt}, rts)
		}
	})

	t.Run("suffix", func(t *testing.T) {
		r, _ := NewTXTRegistry(p, "", "-post", "owner", time.Hour, "wc", nil, false, nil)
		name, rt := r.mapper.toEndpointName("foo.test-zone.example.org")
		assert.Equal(t, "foo.test-zone.example.org", name)
		assert.Equal(t, oldrtypes, rt)

		name, rt = r.mapper.toEndpointName("foo-post.test-zone.example.org")
		assert.Equal(t, "pre-foo.test-zone.example.org", name)
		assert.Equal(t, oldrtypes, rt)

		for _, rt := range endpoint.AllRecordTypes {
			name, rts := r.mapper.toEndpointName(fmt.Sprintf("foo-%s-post.test-zone.example.org", rt))
			assert.Equal(t, "foo.test-zone.example.org", name)
			assert.Equal(t, []string{rt}, rts)
		}
	})
}

func TestRecordsLabelProcessingOldLabel(t *testing.T) {
	ctx := context.Background()
	p := inmemory.NewInMemoryProvider()
	p.CreateZone(testZone)
	p.ApplyChanges(ctx, &plan.Changes{
		Create: []*endpoint.Endpoint{
			endpoint.NewEndpoint("no-owner-record.test.test-zone.example.org", endpoint.RecordTypeTXT,
				"heritage=external-dns,external-dns/owner=owner,external-dns/resource=wurst"),
			endpoint.NewEndpoint("no-owner-record.test.test-zone.example.org", endpoint.RecordTypeA,
				"8.8.8.8"),
			endpoint.NewEndpoint("no-owner-record.test.test-zone.example.org", endpoint.RecordTypeCNAME,
				"to.example.org"),
			endpoint.NewEndpoint("no-owner-record.test.test-zone.example.org", endpoint.RecordTypeAAAA,
				"to.example.org"),
		},
	})
	r, _ := NewTXTRegistry(p, "", "", "owner", time.Hour, "wc", nil, false, nil)
	records, err := r.Records(ctx)
	if err != nil {
		t.Error(err)
	}
	testutils.SortEndpoints(records)
	require.Len(t, records, 2)
	ep := records[1]
	assert.Equal(t, "no-owner-record.test.test-zone.example.org", ep.Name.Fqdn())
	assert.Equal(t, endpoint.RecordTypeTXT, ep.RecordType)
	assert.Equal(t, "heritage=external-dns,external-dns/owner=owner,external-dns/resource=wurst", ep.Targets[0])
	assert.Equal(t, ep.Labels[endpoint.OwnerLabelKey], "owner")
	assert.Equal(t, ep.Labels[endpoint.OwnedRecordLabelKey], "no-owner-record.test.test-zone.example.org")
	assert.Equal(t, ep.Labels[endpoint.ResourceLabelKey], "wurst")

	ep = records[0]
	assert.Equal(t, "no-owner-record.test.test-zone.example.org", ep.Name.Fqdn())
	assert.Equal(t, "8.8.8.8", ep.Targets[0])
	require.Len(t, ep.Labels, 0)
}

/**

helper methods

*/

func newEndpointWithOwner(dnsName, target, recordType, ownerID string) *endpoint.Endpoint {
	return newEndpointWithOwnerAndLabels(dnsName, target, recordType, ownerID, nil)
}

func newEndpointWithOwnerAndOwnedRecord(dnsName, target, recordType, ownerID, ownedRecord string) *endpoint.Endpoint {
	return newEndpointWithOwnerAndLabels(dnsName, target, recordType, ownerID, endpoint.Labels{endpoint.OwnedRecordLabelKey: ownedRecord})
}

func newEndpointWithOwnerAndLabels(dnsName, target, recordType, ownerID string, labels endpoint.Labels) *endpoint.Endpoint {
	e := endpoint.NewEndpoint(dnsName, recordType, target)
	e.Labels[endpoint.OwnerLabelKey] = ownerID
	for k, v := range labels {
		e.Labels[k] = v
	}
	return e
}

func newEndpointWithOwnerResource(dnsName, target, recordType, ownerID, resource string) *endpoint.Endpoint {
	e := endpoint.NewEndpoint(dnsName, recordType, target)
	e.Labels[endpoint.OwnerLabelKey] = ownerID
	e.Labels[endpoint.ResourceLabelKey] = resource
	return e
}
