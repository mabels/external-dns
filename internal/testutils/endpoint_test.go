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

package testutils

import (
	"fmt"
	"sort"

	"sigs.k8s.io/external-dns/endpoint"
)

func ExampleSameEndpoints() {
	eps := []*endpoint.Endpoint{
		{
			Name:    endpoint.NewEndpointNameCommon("example.org"),
			Targets: endpoint.Targets{"load-balancer.org"},
		},
		{
			Name:       endpoint.NewEndpointNameCommon("example.org"),
			Targets:    endpoint.Targets{"load-balancer.org"},
			RecordType: endpoint.RecordTypeTXT,
		},
		{
			Name:       endpoint.NewEndpointNameCommon("abc.com"),
			Targets:    endpoint.Targets{"something"},
			RecordType: endpoint.RecordTypeTXT,
		},
		{
			Name:          endpoint.NewEndpointNameCommon("abc.com"),
			Targets:       endpoint.Targets{"1.2.3.4"},
			RecordType:    endpoint.RecordTypeA,
			SetIdentifier: "test-set-1",
		},
		{
			Name:       endpoint.NewEndpointNameCommon("bbc.com"),
			Targets:    endpoint.Targets{"foo.com"},
			RecordType: endpoint.RecordTypeCNAME,
		},
		{
			Name:       endpoint.NewEndpointNameCommon("cbc.com"),
			Targets:    endpoint.Targets{"foo.com"},
			RecordType: "CNAME",
			RecordTTL:  endpoint.TTL(60),
		},
		{
			Name:    endpoint.NewEndpointNameCommon("example.org"),
			Targets: endpoint.Targets{"load-balancer.org"},
			ProviderSpecific: endpoint.ProviderSpecific{
				endpoint.ProviderSpecificProperty{Name: "foo", Value: "bar"},
			},
		},
	}
	sort.Sort(byAllFields(eps))
	for _, ep := range eps {
		fmt.Println(ep)
	}
	// Output:
	// abc.com 0 IN A test-set-1 1.2.3.4 []
	// abc.com 0 IN TXT  something []
	// bbc.com 0 IN CNAME  foo.com []
	// cbc.com 60 IN CNAME  foo.com []
	// example.org 0 IN   load-balancer.org []
	// example.org 0 IN   load-balancer.org [{foo bar}]
	// example.org 0 IN TXT  load-balancer.org []
}
