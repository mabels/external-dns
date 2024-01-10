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

package cloudflare

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"sigs.k8s.io/external-dns/source"
)

const (
	// cloudFlareCreate is a ChangeAction enum value
	cloudFlareCreate = "CREATE"
	// cloudFlareDelete is a ChangeAction enum value
	cloudFlareDelete = "DELETE"
	// cloudFlareUpdate is a ChangeAction enum value
	cloudFlareUpdate = "UPDATE"
	// defaultCloudFlareRecordTTL 1 = automatic
	defaultCloudFlareRecordTTL = 1
)

// We have to use pointers to bools now, as the upstream cloudflare-go library requires them
// see: https://github.com/cloudflare/cloudflare-go/pull/595

// proxyEnabled is a pointer to a bool true showing the record should be proxied through cloudflare
var proxyEnabled *bool = boolPtr(true)

// proxyDisabled is a pointer to a bool false showing the record should not be proxied through cloudflare
var proxyDisabled *bool = boolPtr(false)

var recordTypeProxyNotSupported = map[string]bool{
	"LOC": true,
	"MX":  true,
	"NS":  true,
	"SPF": true,
	"TXT": true,
	"SRV": true,
}

// cloudFlareDNS is the subset of the CloudFlare API that we actually use.  Add methods as required. Signatures must match exactly.
type cloudFlareDNS interface {
	UserDetails(ctx context.Context) (cloudflare.User, error)
	ZoneIDByName(zoneName string) (string, error)
	ListZones(ctx context.Context, zoneID ...string) ([]cloudflare.Zone, error)
	ListZonesContext(ctx context.Context, opts ...cloudflare.ReqOption) (cloudflare.ZonesResponse, error)
	ZoneDetails(ctx context.Context, zoneID string) (cloudflare.Zone, error)
	ListDNSRecords(ctx context.Context, rc *cloudflare.ResourceContainer, rp cloudflare.ListDNSRecordsParams) ([]cloudflare.DNSRecord, *cloudflare.ResultInfo, error)
	CreateDNSRecord(ctx context.Context, rc *cloudflare.ResourceContainer, rp cloudflare.CreateDNSRecordParams) (cloudflare.DNSRecord, error)
	DeleteDNSRecord(ctx context.Context, rc *cloudflare.ResourceContainer, recordID string) error
	UpdateDNSRecord(ctx context.Context, rc *cloudflare.ResourceContainer, rp cloudflare.UpdateDNSRecordParams) (cloudflare.DNSRecord, error)
}

type zoneService struct {
	service *cloudflare.API
}

func (z zoneService) UserDetails(ctx context.Context) (cloudflare.User, error) {
	return z.service.UserDetails(ctx)
}

func (z zoneService) ListZones(ctx context.Context, zoneID ...string) ([]cloudflare.Zone, error) {
	return z.service.ListZones(ctx, zoneID...)
}

func (z zoneService) ZoneIDByName(zoneName string) (string, error) {
	return z.service.ZoneIDByName(zoneName)
}

func (z zoneService) CreateDNSRecord(ctx context.Context, rc *cloudflare.ResourceContainer, rp cloudflare.CreateDNSRecordParams) (cloudflare.DNSRecord, error) {
	return z.service.CreateDNSRecord(ctx, rc, rp)
}

func (z zoneService) ListDNSRecords(ctx context.Context, rc *cloudflare.ResourceContainer, rp cloudflare.ListDNSRecordsParams) ([]cloudflare.DNSRecord, *cloudflare.ResultInfo, error) {
	return z.service.ListDNSRecords(ctx, rc, rp)
}

func (z zoneService) UpdateDNSRecord(ctx context.Context, rc *cloudflare.ResourceContainer, rp cloudflare.UpdateDNSRecordParams) (cloudflare.DNSRecord, error) {
	return z.service.UpdateDNSRecord(ctx, rc, rp)
}

func (z zoneService) DeleteDNSRecord(ctx context.Context, rc *cloudflare.ResourceContainer, recordID string) error {
	return z.service.DeleteDNSRecord(ctx, rc, recordID)
}

func (z zoneService) ListZonesContext(ctx context.Context, opts ...cloudflare.ReqOption) (cloudflare.ZonesResponse, error) {
	return z.service.ListZonesContext(ctx, opts...)
}

func (z zoneService) ZoneDetails(ctx context.Context, zoneID string) (cloudflare.Zone, error) {
	return z.service.ZoneDetails(ctx, zoneID)
}

// CloudFlareProvider is an implementation of Provider for CloudFlare DNS.
type CloudFlareProvider struct {
	provider.BaseProvider
	Client cloudFlareDNS
	// only consider hosted zones managing domains ending in this suffix
	domainFilter      endpoint.DomainFilter
	zoneIDFilter      provider.ZoneIDFilter
	proxiedByDefault  bool
	DryRun            bool
	DNSRecordsPerPage int
}

// cloudFlareChange differentiates between ChangActions
type cloudFlareChange struct {
	Action         string
	ResourceRecord cloudflare.DNSRecord
}

// RecordParamsTypes is a typeset of the possible Record Params that can be passed to cloudflare-go library
// type RecordParamsTypes interface {
// 	cloudflare.CreateDNSRecordParams | cloudflare.UpdateDNSRecordParams
// }

// getRecordParam is a generic function that returns the appropriate Record Param based on the cloudFlareChange passed in
func getCreateDNSRecordParams(cfc cloudFlareChange) cloudflare.CreateDNSRecordParams {
	return cloudflare.CreateDNSRecordParams{
		Name:     cfc.ResourceRecord.Name,
		TTL:      cfc.ResourceRecord.TTL,
		Proxied:  cfc.ResourceRecord.Proxied,
		Type:     cfc.ResourceRecord.Type,
		Content:  cfc.ResourceRecord.Content,
		Priority: cfc.ResourceRecord.Priority,
		Data:     cfc.ResourceRecord.Data,
	}
}

func getUpdateDNSRecordParam(cfc cloudFlareChange) cloudflare.UpdateDNSRecordParams {
	return cloudflare.UpdateDNSRecordParams{
		Name:     cfc.ResourceRecord.Name,
		TTL:      cfc.ResourceRecord.TTL,
		Proxied:  cfc.ResourceRecord.Proxied,
		Type:     cfc.ResourceRecord.Type,
		Content:  cfc.ResourceRecord.Content,
		Priority: cfc.ResourceRecord.Priority,
		Data:     cfc.ResourceRecord.Data,
	}
}

// NewCloudFlareProvider initializes a new CloudFlare DNS based Provider.
func NewCloudFlareProvider(domainFilter endpoint.DomainFilter, zoneIDFilter provider.ZoneIDFilter, proxiedByDefault bool, dryRun bool, dnsRecordsPerPage int) (*CloudFlareProvider, error) {
	// initialize via chosen auth method and returns new API object
	var (
		config *cloudflare.API
		err    error
	)
	if os.Getenv("CF_API_TOKEN") != "" {
		token := os.Getenv("CF_API_TOKEN")
		if strings.HasPrefix(token, "file:") {
			tokenBytes, err := os.ReadFile(strings.TrimPrefix(token, "file:"))
			if err != nil {
				return nil, fmt.Errorf("failed to read CF_API_TOKEN from file: %w", err)
			}
			token = string(tokenBytes)
		}
		config, err = cloudflare.NewWithAPIToken(token)
	} else {
		config, err = cloudflare.New(os.Getenv("CF_API_KEY"), os.Getenv("CF_API_EMAIL"))
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cloudflare provider: %v", err)
	}
	provider := &CloudFlareProvider{
		// Client: config,
		Client:            zoneService{config},
		domainFilter:      domainFilter,
		zoneIDFilter:      zoneIDFilter,
		proxiedByDefault:  proxiedByDefault,
		DryRun:            dryRun,
		DNSRecordsPerPage: dnsRecordsPerPage,
	}
	return provider, nil
}

// Zones returns the list of hosted zones.
func (p *CloudFlareProvider) Zones(ctx context.Context) ([]cloudflare.Zone, error) {
	result := []cloudflare.Zone{}

	// if there is a zoneIDfilter configured
	// && if the filter isn't just a blank string (used in tests)
	if len(p.zoneIDFilter.ZoneIDs) > 0 && p.zoneIDFilter.ZoneIDs[0] != "" {
		log.Debugln("zoneIDFilter configured. only looking up zone IDs defined")
		for _, zoneID := range p.zoneIDFilter.ZoneIDs {
			log.Debugf("looking up zone %s", zoneID)
			detailResponse, err := p.Client.ZoneDetails(ctx, zoneID)
			if err != nil {
				log.Errorf("zone %s lookup failed, %v", zoneID, err)
				return result, err
			}
			log.WithFields(log.Fields{
				"zoneName": detailResponse.Name,
				"zoneID":   detailResponse.ID,
			}).Debugln("adding zone for consideration")
			result = append(result, detailResponse)
		}
		return result, nil
	}

	log.Debugln("no zoneIDFilter configured, looking at all zones")

	zonesResponse, err := p.Client.ListZonesContext(ctx)
	if err != nil {
		return nil, err
	}

	for _, zone := range zonesResponse.Result {
		if !p.domainFilter.Match(zone.Name) {
			log.Debugf("zone %s not in domain filter", zone.Name)
			continue
		}
		result = append(result, zone)
	}

	return result, nil
}

// Records returns the list of records.
func (p *CloudFlareProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	zones, err := p.Zones(ctx)
	if err != nil {
		return nil, err
	}

	endpoints := []*endpoint.Endpoint{}
	for _, zone := range zones {
		records, err := p.listDNSRecordsWithAutoPagination(ctx, zone.ID)
		if err != nil {
			return nil, err
		}

		// As CloudFlare does not support "sets" of targets, but instead returns
		// a single entry for each name/type/target, we have to group by name
		// and record to allow the planner to calculate the correct plan. See #992.
		endpoints = append(endpoints, groupByNameAndType(zone.Name, records)...)
	}

	return endpoints, nil
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *CloudFlareProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	cloudflareChanges := []*cloudFlareChange{}

	for _, endpoint := range changes.Create {
		for _, target := range endpoint.Targets {
			cloudflareChanges = append(cloudflareChanges, p.newCloudFlareChange(cloudFlareCreate, endpoint, target))
		}
	}

	for i, desired := range changes.UpdateNew {
		current := changes.UpdateOld[i]

		add, remove, leave := provider.Difference(current.Targets, desired.Targets)

		for _, a := range remove {
			cloudflareChanges = append(cloudflareChanges, p.newCloudFlareChange(cloudFlareDelete, current, a))
		}

		for _, a := range add {
			cloudflareChanges = append(cloudflareChanges, p.newCloudFlareChange(cloudFlareCreate, desired, a))
		}

		for _, a := range leave {
			cloudflareChanges = append(cloudflareChanges, p.newCloudFlareChange(cloudFlareUpdate, desired, a))
		}
	}

	for _, endpoint := range changes.Delete {
		for _, target := range endpoint.Targets {
			cloudflareChanges = append(cloudflareChanges, p.newCloudFlareChange(cloudFlareDelete, endpoint, target))
		}
	}

	return p.submitChanges(ctx, cloudflareChanges)
}

func (p *CloudFlareProvider) PropertyValuesEqual(name string, previous string, current string) bool {
	if name == source.CloudflareProxiedKey {
		return plan.CompareBoolean(p.proxiedByDefault, name, previous, current)
	}

	return p.BaseProvider.PropertyValuesEqual(name, previous, current)
}

// submitChanges takes a zone and a collection of Changes and sends them as a single transaction.
func (p *CloudFlareProvider) submitChanges(ctx context.Context, changes []*cloudFlareChange) error {
	// return early if there is nothing to change
	if len(changes) == 0 {
		return nil
	}

	zones, err := p.Zones(ctx)
	if err != nil {
		return err
	}
	// separate into per-zone change sets to be passed to the API.
	changesByZone := p.changesByZone(zones, changes)

	for zoneID, changes := range changesByZone {
		records, err := p.listDNSRecordsWithAutoPagination(ctx, zoneID)
		if err != nil {
			return fmt.Errorf("could not fetch records from zone, %v", err)
		}
		for _, change := range changes {
			logFields := log.Fields{
				"record": change.ResourceRecord.Name,
				"type":   change.ResourceRecord.Type,
				"ttl":    change.ResourceRecord.TTL,
				"action": change.Action,
				"zone":   zoneID,
			}

			log.WithFields(logFields).Info("Changing record.")

			if p.DryRun {
				continue
			}

			resourceContainer := cloudflare.ZoneIdentifier(zoneID)
			if change.Action == cloudFlareUpdate {
				recordID := p.getRecordID(records, change.ResourceRecord)
				if recordID == "" {
					log.WithFields(logFields).Errorf("failed to find previous record: %v", change.ResourceRecord)
					continue
				}
				recordParam := getUpdateDNSRecordParam(*change)
				recordParam.ID = recordID
				_, err := p.Client.UpdateDNSRecord(ctx, resourceContainer, recordParam)
				if err != nil {
					log.WithFields(logFields).Errorf("failed to update record: %v", err)
				}
			} else if change.Action == cloudFlareDelete {
				recordID := p.getRecordID(records, change.ResourceRecord)
				if recordID == "" {
					log.WithFields(logFields).Errorf("failed to find previous record: %v", change.ResourceRecord)
					continue
				}
				err := p.Client.DeleteDNSRecord(ctx, resourceContainer, recordID)
				if err != nil {
					log.WithFields(logFields).Errorf("failed to delete record: %v", err)
				}
			} else if change.Action == cloudFlareCreate {
				recordParam := getCreateDNSRecordParams(*change)
				_, err := p.Client.CreateDNSRecord(ctx, resourceContainer, recordParam)
				if err != nil {
					log.WithFields(logFields).Errorf("failed to create record: %v", err)
				}
			}
		}
	}
	return nil
}

// AdjustEndpoints modifies the endpoints as needed by the specific provider
func (p *CloudFlareProvider) AdjustEndpoints(endpoints []*endpoint.Endpoint) []*endpoint.Endpoint {
	adjustedEndpoints := []*endpoint.Endpoint{}
	for _, e := range endpoints {
		if shouldBeProxied(e, p.proxiedByDefault) {
			e.RecordTTL = 0
		}
		found := false
		for _, ps := range e.ProviderSpecific {
			if ps.Name == source.CloudflareProxiedKey {
				found = true
				break
			}
		}
		if !found {
			e.ProviderSpecific = append(e.ProviderSpecific, endpoint.ProviderSpecificProperty{
				Name:  source.CloudflareProxiedKey,
				Value: strconv.FormatBool(p.proxiedByDefault),
			})
		}

		adjustedEndpoints = append(adjustedEndpoints, e)
	}
	return adjustedEndpoints
}

// changesByZone separates a multi-zone change into a single change per zone.
func (p *CloudFlareProvider) changesByZone(zones []cloudflare.Zone, changeSet []*cloudFlareChange) map[string][]*cloudFlareChange {
	changes := make(map[string][]*cloudFlareChange)
	zoneNameIDMapper := provider.ZoneIDName{}

	for _, z := range zones {
		zoneNameIDMapper.Add(z.ID, z.Name)
		changes[z.ID] = []*cloudFlareChange{}
	}

	for _, c := range changeSet {
		zoneID, _ := zoneNameIDMapper.FindZone(c.ResourceRecord.Name)
		if zoneID == "" {
			log.Debugf("Skipping record %s because no hosted zone matching record DNS Name was detected", c.ResourceRecord.Name)
			continue
		}
		changes[zoneID] = append(changes[zoneID], c)
	}

	return changes
}

func (p *CloudFlareProvider) getRecordID(records []cloudflare.DNSRecord, record cloudflare.DNSRecord) string {
	for _, zoneRecord := range records {
		if zoneRecord.Name == record.Name && zoneRecord.Type == record.Type && zoneRecord.Content == record.Content {
			return zoneRecord.ID
		}
	}
	return ""
}

var reDNSRecordTypeMX = regexp.MustCompile(`^(\d+)\s+(.+)$`)
var reDNSRecordTypeSRV = regexp.MustCompile(`^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$`)
var reDNSNameSRV = regexp.MustCompile(`^([^\.]+)\.([^\.]+)\.(.+)$`)

type cfSrvData struct {
	Name     string `json:"name"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Proto    string `json:"proto"`
	Service  string `json:"service"`
	Target   string `json:"target"`
	Weight   uint16 `json:"weight"`
}

func applyRecordType(ep *endpoint.Endpoint, target string, rrec *cloudflare.DNSRecord) *cloudflare.DNSRecord {
	// switch e.RecordType {
	// case endpoint.RecordTypeCNAME, endpoint.RecordTypeMX:
	// 	// cloudflare strips the trailing dot from CNAME/MX records
	// 	// so we do the same to ensure idempotency in the read
	// 	// records from k8s
	// 	e.Targets = []string{strings.TrimRight(e.Targets[0], ".")}
	// }

	switch ep.RecordType {
	case endpoint.RecordTypeCNAME:
		rrec.Content = strings.TrimRight(target, ".")
	case endpoint.RecordTypeSRV:
		// 10 5 443 matrix.test.com.
		parsed := reDNSRecordTypeSRV.FindStringSubmatch(target)
		if len(parsed) == 5 {
			priority, _ := strconv.ParseUint(parsed[1], 10, 16)
			prio16 := uint16(priority)
			rrec.Priority = &prio16
			weight, _ := strconv.ParseUint(parsed[2], 10, 16)
			port, _ := strconv.ParseUint(parsed[3], 10, 16)
			rrec.Content = fmt.Sprintf("%d\t%d\t%d\t%s", priority, weight, port, strings.TrimRight(parsed[4], "."))
			parsedName := reDNSNameSRV.FindStringSubmatch(strings.TrimRight(ep.Name.Fqdn(), "."))
			if len(parsedName) == 4 {
				rrec.Data = cfSrvData{
					Name:     parsedName[3],
					Port:     uint16(port),
					Priority: uint16(priority),
					Proto:    parsedName[2],
					Service:  parsedName[1],
					Target:   parsed[4],
					Weight:   uint16(weight),
				}
			}
		}

	case endpoint.RecordTypeMX:
		parsed := reDNSRecordTypeMX.FindStringSubmatch(target)
		if len(parsed) == 3 {
			priority, err := strconv.ParseUint(parsed[1], 10, 16)
			if err == nil {
				prio16 := uint16(priority)
				rrec.Priority = &prio16
			}
			rrec.Content = strings.TrimRight(parsed[2], ".")
		}
	}
	return rrec
}

func (p *CloudFlareProvider) newCloudFlareChange(action string, endpoint *endpoint.Endpoint, target string) *cloudFlareChange {
	ttl := defaultCloudFlareRecordTTL
	proxied := shouldBeProxied(endpoint, p.proxiedByDefault)

	if endpoint.RecordTTL.IsConfigured() {
		ttl = int(endpoint.RecordTTL)
	}
	rrec := cloudflare.DNSRecord{
		Name:    endpoint.Name.Fqdn(),
		TTL:     ttl,
		Proxied: &proxied,
		Type:    endpoint.RecordType,
		Content: target,
	}
	applyRecordType(endpoint, target, &rrec)
	return &cloudFlareChange{
		Action:         action,
		ResourceRecord: rrec,
	}
}

// listDNSRecords performs automatic pagination of results on requests to cloudflare.ListDNSRecords with custom per_page values
func (p *CloudFlareProvider) listDNSRecordsWithAutoPagination(ctx context.Context, zoneID string) ([]cloudflare.DNSRecord, error) {
	var records []cloudflare.DNSRecord
	resultInfo := cloudflare.ResultInfo{PerPage: p.DNSRecordsPerPage, Page: 1}
	params := cloudflare.ListDNSRecordsParams{ResultInfo: resultInfo}
	for {
		pageRecords, resultInfo, err := p.Client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), params)
		if err != nil {
			return nil, err
		}

		records = append(records, pageRecords...)
		params.ResultInfo = resultInfo.Next()
		if params.ResultInfo.Done() {
			break
		}
	}
	return records, nil
}

func shouldBeProxied(endpoint *endpoint.Endpoint, proxiedByDefault bool) bool {
	proxied := proxiedByDefault

	for _, v := range endpoint.ProviderSpecific {
		if v.Name == source.CloudflareProxiedKey {
			b, err := strconv.ParseBool(v.Value)
			if err != nil {
				log.Errorf("Failed to parse annotation [%s]: %v", source.CloudflareProxiedKey, err)
			} else {
				proxied = b
			}
			break
		}
	}

	if recordTypeProxyNotSupported[endpoint.RecordType] {
		proxied = false
	}
	return proxied
}

func groupByNameAndType(zoneName string, records []cloudflare.DNSRecord) []*endpoint.Endpoint {
	endpoints := []*endpoint.Endpoint{}

	// group supported records by name and type
	groups := map[string][]cloudflare.DNSRecord{}

	for _, r := range records {
		// if !provider.SupportedRecordType(r.Type) {
		// 	continue
		// }

		groupBy := r.Name + r.Type
		if _, ok := groups[groupBy]; !ok {
			groups[groupBy] = []cloudflare.DNSRecord{}
		}

		groups[groupBy] = append(groups[groupBy], r)
	}

	// create single endpoint with all the targets for each name/type
	for _, records := range groups {
		targets := make([]string, len(records))
		for i, record := range records {
			targets[i] = record.Content
		}
		if !endpoint.IsValidRecordType(records[0].Type) {
			continue
		}
		switch records[0].Type {
		case endpoint.RecordTypeMX:
			// cloudflare returns MX records without priority in the content
			for i, target := range targets {
				targets[i] = fmt.Sprintf("%d %s", *records[i].Priority, target)
			}
		case endpoint.RecordTypeSRV:
			// cloudflare returns SRV records without priority and weight in the content
			for i, record := range records {
				data := record.Data.(map[string]interface{})
				weight := uint16(data["weight"].(float64))
				port := uint16(data["port"].(float64))
				target := data["target"].(string)
				targets[i] = fmt.Sprintf("%d %d %d %s", *record.Priority,
					weight, port, target)
			}
		}
		endpoints = append(endpoints,
			endpoint.NewEndpointWithTTL(
				endpoint.NewEndpointName(records[0].Name, zoneName),
				records[0].Type,
				endpoint.TTL(records[0].TTL),
				targets...).
				WithProviderSpecific(source.CloudflareProxiedKey, strconv.FormatBool(*records[0].Proxied)),
		)
	}

	return endpoints
}

// boolPtr is used as a helper function to return a pointer to a boolean
// Needed because some parameters require a pointer.
func boolPtr(b bool) *bool {
	return &b
}
