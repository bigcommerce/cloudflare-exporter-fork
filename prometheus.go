package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/biter777/countries"
	cfaccounts "github.com/cloudflare/cloudflare-go/v4/accounts"
	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
)

type Metric struct {
	Name      string
	Help      string
	Labels    []string
	Type      string
	collector prometheus.Collector
}

func (m Metric) RecordValueWithLabels(value any, labels ...string) {
	var floatValue float64
	switch value := value.(type) {
	case float32:
		floatValue = float64(value)
	case float64:
		floatValue = value
	case int:
		floatValue = float64(value)
	case int64:
		floatValue = float64(value)
	case uint:
		floatValue = float64(value)
	case uint64:
		floatValue = float64(value)
	default:
		panic(fmt.Sprintf("unsupported value type: %T for metric", value))
	}

	switch m.Type {
	case "counter":
		m.collector.(*prometheus.CounterVec).WithLabelValues(labels...).Add(floatValue)
	case "gauge":
		m.collector.(*prometheus.GaugeVec).WithLabelValues(labels...).Set(floatValue)
	case "histogram":
		m.collector.(*prometheus.HistogramVec).WithLabelValues(labels...).Observe(floatValue)
	case "summary":
		m.collector.(*prometheus.SummaryVec).WithLabelValues(labels...).Observe(floatValue)
	default:
		panic(fmt.Sprintf("unknown metric type: %s", m.Type))
	}
}

func MustRegister(m Metric) {
	switch m.Type {
	case "counter":
		m.collector = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: m.Name,
			Help: m.Help,
		}, m.Labels)
	case "histogram":
		m.collector = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: m.Name,
			Help: m.Help,
		}, m.Labels)
	case "gauge":
		m.collector = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: m.Name,
			Help: m.Help,
		}, m.Labels)
	case "summary":
		m.collector = prometheus.NewSummaryVec(prometheus.SummaryOpts{
			Name: m.Name,
			Help: m.Help,
		}, m.Labels)
	default:
		panic(fmt.Sprintf("unknown metric type: %s", m.Type))
	}
}

var Metrics = map[string]Metric{
	"zoneRequestsTotal": {
		Name:   "cloudflare_zone_requests_total",
		Help:   "Number of requests for zone",
		Labels: []string{"zone", "account"},
		Type:   "counter",
	},
	"zoneRequestsCached": {
		Name:   "cloudflare_zone_requests_cached",
		Help:   "Number of cached requests for zone",
		Labels: []string{"zone", "account"},
		Type:   "counter"},
	"zoneRequestsSslEncrypted": {
		Name:   "cloudflare_zone_requests_ssl_encrypted",
		Help:   "Number of encrypted requests for zone",
		Labels: []string{"zone", "account"},
		Type:   "counter"},
	"zoneRequestsContentType": {
		Name:   "cloudflare_zone_requests_content_type",
		Help:   "Number of request for zone per content type",
		Labels: []string{"zone", "account", "content_type"},
		Type:   "counter"},
	"zoneRequestsCountry": {
		Name:   "cloudflare_zone_requests_country",
		Help:   "Number of request for zone per country",
		Labels: []string{"zone", "account", "country", "region"},
		Type:   "counter"},
	"zoneRequestsStatus": {
		Name:   "cloudflare_zone_requests_status",
		Help:   "Number of request for zone per HTTP status",
		Labels: []string{"zone", "account", "status"},
		Type:   "counter"},
	"zoneRequestsBrowserMapPageViewsCount": {
		Name:   "cloudflare_zone_requests_browser_map_page_views_count",
		Help:   "Number of successful requests for HTML pages per zone",
		Labels: []string{"zone", "account", "family"},
		Type:   "counter"},
	"zoneRequestsOriginStatusCountryHost": {
		Name:   "cloudflare_zone_requests_origin_status_country_host",
		Help:   "Count of not cached requests for zone per origin HTTP status per country per host",
		Labels: []string{"zone", "account", "status", "country", "host"},
		Type:   "counter"},
	"zoneRequestsStatusCountryHost": {
		Name:   "cloudflare_zone_requests_status_country_host",
		Help:   "Count of requests for zone per edge HTTP status per country per host",
		Labels: []string{"zone", "account", "status", "country", "host"},
		Type:   "counter"},
	"zoneBandwidthTotal": {
		Name:   "cloudflare_zone_bandwidth_total",
		Help:   "Total bandwidth per zone in bytes",
		Labels: []string{"zone", "account"},
		Type:   "counter"},
	"zoneBandwidthCached": {
		Name:   "cloudflare_zone_bandwidth_cached",
		Help:   "Cached bandwidth per zone in bytes",
		Labels: []string{"zone", "account"},
		Type:   "counter"},
	"zoneBandwidthSslEncrypted": {
		Name:   "cloudflare_zone_bandwidth_ssl_encrypted",
		Help:   "Encrypted bandwidth per zone in bytes",
		Labels: []string{"zone", "account"},
		Type:   "counter"},
	"zoneBandwidthContentType": {
		Name:   "cloudflare_zone_bandwidth_content_type",
		Help:   "Bandwidth per zone per content type",
		Labels: []string{"zone", "account", "content_type"},
		Type:   "counter"},
	"zoneBandwidthCountry": {
		Name:   "cloudflare_zone_bandwidth_country",
		Help:   "Bandwidth per country per zone",
		Labels: []string{"zone", "account", "country", "region"},
		Type:   "counter"},
	"zoneThreatsTotal": {
		Name:   "cloudflare_zone_threats_total",
		Help:   "Threats per zone",
		Labels: []string{"zone", "account"},
		Type:   "counter"},
	"zoneThreatsCountry": {
		Name:   "cloudflare_zone_threats_country",
		Help:   "Threats per zone per country",
		Labels: []string{"zone", "account", "country", "region"},
		Type:   "counter"},
	"zoneThreatsType": {
		Name:   "cloudflare_zone_threats_type",
		Help:   "Threats per zone per type",
		Labels: []string{"zone", "account", "type"},
		Type:   "counter"},
	"zonePageviewsTotal": {
		Name:   "cloudflare_zone_pageviews_total",
		Help:   "Pageviews per zone",
		Labels: []string{"zone", "account"},
		Type:   "counter"},
	"zoneUniquesTotal": {
		Name:   "cloudflare_zone_uniques_total",
		Help:   "Uniques per zone",
		Labels: []string{"zone", "account"},
		Type:   "counter"},
	"zoneColocationVisits": {
		Name:   "cloudflare_zone_colocation_visits",
		Help:   "Total visits per colocation",
		Labels: []string{"zone", "account", "colocation", "host"},
		Type:   "counter"},
	"zoneColocationEdgeResponseBytes": {
		Name:   "cloudflare_zone_colocation_edge_response_bytes",
		Help:   "Edge response bytes per colocation",
		Labels: []string{"zone", "account", "colocation", "host"},
		Type:   "counter"},
	"zoneColocationRequestsTotal": {
		Name:   "cloudflare_zone_colocation_requests_total",
		Help:   "Total requests per colocation",
		Labels: []string{"zone", "account", "colocation", "host"},
		Type:   "counter"},
	"zoneFirewallEventsCount": {
		Name:   "cloudflare_zone_firewall_events_count",
		Help:   "Count of Firewall events",
		Labels: []string{"zone", "account", "action", "source", "rule", "host", "country"},
		Type:   "counter"},
	"zoneHealthCheckEventsOriginCount": {
		Name:   "cloudflare_zone_health_check_events_origin_count",
		Help:   "Number of Heath check events per region per origin",
		Labels: []string{"zone", "account", "health_status", "origin_ip", "region", "fqdn"},
		Type:   "counter"},
	"workerRequestsCount": {
		Name:   "cloudflare_worker_requests_count",
		Help:   "Number of requests sent to worker by script name",
		Labels: []string{"script_name", "account", "status"},
		Type:   "counter"},
	"workerErrorsCount": {
		Name:   "cloudflare_worker_errors_count",
		Help:   "Number of errors by script name",
		Labels: []string{"script_name", "account", "status"},
		Type:   "counter"},
	"workerCpuTime": {
		Name:   "cloudflare_worker_cpu_time",
		Help:   "CPU time quantiles by script name",
		Labels: []string{"script_name", "account", "status", "quantile"},
		Type:   "gauge"},
	"workerDuration": {
		Name:   "cloudflare_worker_duration",
		Help:   "Duration quantiles by script name (GB*s)",
		Labels: []string{"script_name", "account", "status", "quantile"},
		Type:   "gauge"},
	"zonePoolHealthStatus": {
		Name:   "cloudflare_zone_pool_health_status",
		Help:   "Reports the health of a pool, 1 for healthy, 0 for unhealthy.",
		Labels: []string{"zone", "account", "load_balancer_name", "pool_name"},
		Type:   "gauge"},
	"poolOriginHealthStatus": {
		Name:   "cloudflare_pool_origin_health_status",
		Help:   "Reports the origin health of a pool, 1 for healthy, 0 for unhealthy.",
		Labels: []string{"account", "pool_name", "origin_name", "ip"},
		Type:   "gauge"},
	"zonePoolRequestsTotal": {
		Name:   "cloudflare_zone_pool_requests_total",
		Help:   "Requests per pool",
		Labels: []string{"zone", "account", "load_balancer_name", "pool_name", "origin_name"},
		Type:   "counter"},
	"logpushFailedJobsAccountCount": {
		Name:   "cloudflare_logpush_failed_jobs_account_count",
		Help:   "Number of failed logpush jobs on the account level",
		Labels: []string{"account", "destination", "job_id", "final"},
		Type:   "counter"},
	"logpushFailedJobsZoneCount": {
		Name:   "cloudflare_logpush_failed_jobs_zone_count",
		Help:   "Number of failed logpush jobs on the zone level",
		Labels: []string{"destination", "job_id", "final"},
		Type:   "counter"},
	"cloudflare_r2_storage_total_bytes": {
		Name:   "cloudflare_r2_storage_total_bytes",
		Help:   "Total storage used by R2",
		Labels: []string{"account"},
		Type:   "gauge"},
	"cloudflare_r2_storage_bytes": {
		Name:   "cloudflare_r2_storage_bytes",
		Help:   "Storage used by R2",
		Labels: []string{"account", "bucket"},
		Type:   "gauge"},
	"cloudflare_r2_operation_count": {
		Name:   "cloudflare_r2_operation_count",
		Help:   "Number of operations performed by R2",
		Labels: []string{"account", "bucket", "operation"},
		Type:   "gauge"},
	"tunnelInfo": {
		Name:   "cloudflare_tunnel_info",
		Help:   "Reports Cloudflare Tunnel details",
		Labels: []string{"account", "tunnel_id", "tunnel_name", "tunnel_type"},
		Type:   "gauge"},
	"tunnelHealthStatus": {
		Name:   "cloudflare_tunnel_health_status",
		Help:   "Reports the health of a Cloudflare Tunnel, 0 for unhealthy, 1 for healthy, 2 for degraded, 3 for inactive",
		Labels: []string{"account", "tunnel_id"},
		Type:   "gauge"},
	"tunnelConnectorInfo": {
		Name:   "cloudflare_tunnel_connector_info",
		Help:   "Reports Cloudflare Tunnel connector details",
		Labels: []string{"account", "tunnel_id", "client_id", "version", "arch", "origin_ip"},
		Type:   "gauge"},
	"tunnelConnectorActiveConnections": {
		Name:   "cloudflare_tunnel_connector_active_connections",
		Help:   "Reports number of active connections for a Cloudflare Tunnel connector",
		Labels: []string{"account", "tunnel_id", "client_id"},
		Type:   "gauge"},
	"dnsFirewallQueryCount": {
		Name:   "cloudflare_dns_firewall_query_count",
		Help:   "DNS Firewall query count by query type and response code",
		Labels: []string{"account_id", "account_name", "dns_firewall_id", "query_type", "response_code"},
		Type:   "gauge"},
}

func mustRegisterMetrics(deniedMetrics []string) {
	for _, metric := range Metrics {
		if !slices.Contains(deniedMetrics, metric.Name) {
			MustRegister(metric)
		}
	}
}

func fetchLoadblancerPoolsHealth(account cfaccounts.Account, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	pools := fetchLoadblancerPools(account)
	if pools == nil {
		return
	}

	for _, pool := range pools {
		if !pool.Enabled { // not enabled, no health values
			continue
		}
		if pool.Monitor == "" { // No monitor, no health values
			continue
		}
		for _, o := range pool.Origins {
			if !o.Enabled { // not enabled, no health values
				continue
			}
			healthy := 1 // Assume healthy
			if o.JSON.ExtraFields["healthy"].Raw() == "false" {
				healthy = 0 // Unhealthy
			}
			Metrics["cloudflare_pool_origin_health_status"].RecordValueWithLabels(healthy, account.Name, pool.Name, o.Name, o.Address)
		}
	}
}

func fetchWorkerAnalytics(account cfaccounts.Account, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	r, err := fetchWorkerTotals(account.ID)
	if err != nil {
		log.Error("failed to fetch worker analytics for account ", account.ID, ": ", err)
		return
	}

	// Replace spaces with hyphens and convert to lowercase
	accountName := strings.ToLower(strings.ReplaceAll(account.Name, " ", "-"))

	for _, a := range r.Viewer.Accounts {
		for _, w := range a.WorkersInvocationsAdaptive {
			Metrics["workerRequestsCount"].RecordValueWithLabels(w.Sum.Requests, w.Dimensions.ScriptName, accountName, w.Dimensions.Status)
			Metrics["workerErrorsCount"].RecordValueWithLabels(w.Sum.Errors, w.Dimensions.ScriptName, accountName, w.Dimensions.Status)
			Metrics["workerCpuTime"].RecordValueWithLabels(w.Quantiles.CPUTimeP50, w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P50")
			Metrics["workerCpuTime"].RecordValueWithLabels(w.Quantiles.CPUTimeP75, w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P75")
			Metrics["workerCpuTime"].RecordValueWithLabels(w.Quantiles.CPUTimeP99, w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P99")
			Metrics["workerCpuTime"].RecordValueWithLabels(w.Quantiles.CPUTimeP999, w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P999")
			Metrics["workerDuration"].RecordValueWithLabels(w.Quantiles.DurationP50, w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P50")
			Metrics["workerDuration"].RecordValueWithLabels(w.Quantiles.DurationP75, w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P75")
			Metrics["workerDuration"].RecordValueWithLabels(w.Quantiles.DurationP99, w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P99")
			Metrics["workerDuration"].RecordValueWithLabels(w.Quantiles.DurationP999, w.Dimensions.ScriptName, accountName, w.Dimensions.Status, "P999")
		}
	}
}

func fetchLogpushAnalyticsForAccount(account cfaccounts.Account, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	if viper.GetBool("free_tier") {
		return
	}

	r, err := fetchLogpushAccount(account.ID)

	if err != nil {
		log.Error("failed to fetch logpush analytics for account ", account.ID, ": ", err)
		return
	}

	for _, acc := range r.Viewer.Accounts {
		for _, LogpushHealthAdaptiveGroup := range acc.LogpushHealthAdaptiveGroups {
			Metrics["logpushFailedJobsAccountCount"].RecordValueWithLabels(float64(LogpushHealthAdaptiveGroup.Count),
				account.ID,
				LogpushHealthAdaptiveGroup.Dimensions.DestinationType,
				strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.JobID),
				strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.Final),
			)
		}
	}
}

func fetchR2StorageForAccount(account cfaccounts.Account, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	r, err := fetchR2Account(account.ID)

	if err != nil {
		return
	}
	for _, acc := range r.Viewer.Accounts {
		var totalStorage uint64
		for _, bucket := range acc.R2StorageGroups {
			totalStorage += bucket.Max.PayloadSize
			Metrics["cloudflare_r2_storage_bytes"].RecordValueWithLabels(float64(bucket.Max.PayloadSize), account.Name, bucket.Dimensions.BucketName)
		}
		for _, operation := range acc.R2StorageOperations {
			Metrics["cloudflare_r2_operation_count"].RecordValueWithLabels(float64(operation.Sum.Requests), account.Name, operation.Dimensions.BucketName, operation.Dimensions.Action)
		}
		Metrics["cloudflare_r2_storage_total_bytes"].RecordValueWithLabels(float64(totalStorage), account.Name)
	}
}

func fetchLogpushAnalyticsForZone(zones []cfzones.Zone, wg *sync.WaitGroup, _ []string) {
	wg.Add(1)
	defer wg.Done()

	if viper.GetBool("free_tier") {
		return
	}

	zoneIDs := extractZoneIDs(zones)
	if len(zoneIDs) == 0 {
		return
	}

	r, err := fetchLogpushZone(zoneIDs)

	if err != nil {
		log.Error("failed to fetch logpush analytics for zones: ", err)
		return
	}

	for _, zone := range r.Viewer.Zones {
		for _, LogpushHealthAdaptiveGroup := range zone.LogpushHealthAdaptiveGroups {
			Metrics["logpushFailedJobsZoneCount"].RecordValueWithLabels(
				float64(LogpushHealthAdaptiveGroup.Count),
				LogpushHealthAdaptiveGroup.Dimensions.DestinationType,
				strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.JobID),
				strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.Final),
			)
		}
	}
}

func fetchDNSFirewallAnalytics(account cfaccounts.Account, wg *sync.WaitGroup, deniedMetricsSet []string) {
	wg.Add(1)
	defer wg.Done()

	r, err := fetchDNSFirewallTotals(account.ID)
	if err != nil {
		return
	}

	for _, a := range r.Viewer.Accounts {
		for _, d := range a.DNSFirewallAnalyticsAdaptiveGroups {
			if !slices.Contains(deniedMetricsSet, "dnsFirewallQueryCount") {
				Metrics["dnsFirewallQueryCount"].RecordValueWithLabels(
					float64(d.Count),
					account.ID,
					account.Name,
					d.Dimensions.ClusterTag,
					d.Dimensions.QueryType,
					d.Dimensions.ResponseCode,
				)
			}
		}
	}
}

func fetchZoneColocationAnalytics(zones []cfzones.Zone, wg *sync.WaitGroup, deniedMetricsSet []string) {
	wg.Add(1)
	defer wg.Done()

	// Colocation metrics are not available in non-enterprise zones
	if viper.GetBool("free_tier") {
		return
	}

	zoneIDs := extractZoneIDs(zones)
	if len(zoneIDs) == 0 {
		return
	}

	r, err := fetchColoTotals(zoneIDs)
	if err != nil {
		log.Error("failed to fetch colocation analytics for zones: ", err)
		return
	}
	for _, z := range r.Viewer.Zones {
		cg := z.ColoGroups
		name, account := findZoneAccountName(zones, z.ZoneTag)
		for _, c := range cg {
			if !slices.Contains(deniedMetricsSet, "zoneColocationVisits") {
				Metrics["zoneColocationVisits"].RecordValueWithLabels(float64(c.Sum.Visits), name, account, c.Dimensions.ColoCode, c.Dimensions.Host)
			}
			if !slices.Contains(deniedMetricsSet, "zoneColocationEdgeResponseBytes") {
				Metrics["zoneColocationEdgeResponseBytes"].RecordValueWithLabels(float64(c.Sum.EdgeResponseBytes), name, account, c.Dimensions.ColoCode, c.Dimensions.Host)
			}
			if !slices.Contains(deniedMetricsSet, "zoneColocationRequestsTotal") {
				Metrics["zoneColocationRequestsTotal"].RecordValueWithLabels(float64(c.Count), name, account, c.Dimensions.ColoCode, c.Dimensions.Host)
			}
		}
	}
}

func fetchZoneAnalytics(zones []cfzones.Zone, wg *sync.WaitGroup, deniedMetricsSet []string) {
	wg.Add(1)
	defer wg.Done()

	// None of the below referenced metrics are available in the free tier
	if viper.GetBool("free_tier") {
		return
	}

	zoneIDs := extractZoneIDs(zones)
	if len(zoneIDs) == 0 {
		return
	}

	r, err := fetchZoneTotals(zoneIDs)
	if err != nil {
		log.Error("failed to fetch zone analytics: ", err)
		return
	}

	for _, z := range r.Viewer.Zones {
		name, account := findZoneAccountName(zones, z.ZoneTag)
		z := z

		addHTTPGroups(&z, name, account, deniedMetricsSet)
		addFirewallGroups(&z, name, account, deniedMetricsSet)
		addHealthCheckGroups(&z, name, account, deniedMetricsSet)
		addHTTPAdaptiveGroups(&z, name, account, deniedMetricsSet)
	}
}

func addHTTPGroups(z *zoneResp, name string, account string, deniedMetricsSet []string) {
	// Nothing to do.
	if len(z.HTTP1mGroups) == 0 {
		return
	}

	zt := z.HTTP1mGroups[0]

	if !slices.Contains(deniedMetricsSet, "zoneRequestTotal") {
		Metrics["zoneRequestsTotal"].RecordValueWithLabels(zt.Sum.Requests, name, account)
	}
	if !slices.Contains(deniedMetricsSet, "zoneRequestCached") {
		Metrics["zoneRequestsCached"].RecordValueWithLabels(zt.Sum.CachedRequests, name, account)
	}
	if !slices.Contains(deniedMetricsSet, "zoneRequestSSLEncrypted") {
		Metrics["zoneRequestsSslEncrypted"].RecordValueWithLabels(zt.Sum.EncryptedRequests, name, account)
	}

	for _, ct := range zt.Sum.ContentType {
		if !slices.Contains(deniedMetricsSet, "zoneRequestContentType") {
			Metrics["zoneRequestsContentType"].RecordValueWithLabels(ct.Requests, name, account, ct.EdgeResponseContentType)
		}
		if !slices.Contains(deniedMetricsSet, "zoneBandwidthContentType") {
			Metrics["zoneBandwidthContentType"].RecordValueWithLabels(ct.Bytes, name, account, ct.EdgeResponseContentType)
		}
	}

	for _, country := range zt.Sum.Country {
		c := countries.ByName(country.ClientCountryName)
		region := c.Info().Region.Info().Name

		if !slices.Contains(deniedMetricsSet, "zoneRequestCountry") {
			Metrics["zoneRequestsCountry"].RecordValueWithLabels(country.Requests, name, account, country.ClientCountryName, region)
		}
		if !slices.Contains(deniedMetricsSet, "zoneBandwidthCountry") {
			Metrics["zoneBandwidthCountry"].RecordValueWithLabels(country.Bytes, name, account, country.ClientCountryName, region)
		}
		if !slices.Contains(deniedMetricsSet, "zoneThreatsCountry") {
			Metrics["zoneThreatsCountry"].RecordValueWithLabels(country.Threats, name, account, country.ClientCountryName, region)
		}
	}

	if !slices.Contains(deniedMetricsSet, "zoneRequestHTTPStatus") {
		for _, status := range zt.Sum.ResponseStatus {
			Metrics["zoneRequestsStatus"].RecordValueWithLabels(status.Requests, name, account, strconv.Itoa(status.EdgeResponseStatus))
		}
	}

	if !slices.Contains(deniedMetricsSet, "zoneRequestBrowserMap") {
		for _, browser := range zt.Sum.BrowserMap {
			Metrics["zoneRequestsBrowserMapPageViewsCount"].RecordValueWithLabels(browser.PageViews, name, account, browser.UaBrowserFamily)
		}
	}

	if !slices.Contains(deniedMetricsSet, "zoneBandwidthTotal") {
		Metrics["zoneBandwidthTotal"].RecordValueWithLabels(zt.Sum.Bytes, name, account)
	}
	if !slices.Contains(deniedMetricsSet, "zoneBandwidthCached") {
		Metrics["zoneBandwidthCached"].RecordValueWithLabels(zt.Sum.CachedBytes, name, account)
	}
	if !slices.Contains(deniedMetricsSet, "zoneBandwidthSSLEncrypted") {
		Metrics["zoneBandwidthSslEncrypted"].RecordValueWithLabels(zt.Sum.EncryptedBytes, name, account)
	}

	if !slices.Contains(deniedMetricsSet, "zoneThreatsTotal") {
		Metrics["zoneThreatsTotal"].RecordValueWithLabels(zt.Sum.Threats, name, account)
	}

	if !slices.Contains(deniedMetricsSet, "zoneThreatsType") {
		for _, t := range zt.Sum.ThreatPathing {
			Metrics["zoneThreatsType"].RecordValueWithLabels(t.Requests, name, account, t.Name)
		}
	}

	if !slices.Contains(deniedMetricsSet, "zonePageviewsTotal") {
		Metrics["zonePageviewsTotal"].RecordValueWithLabels(zt.Sum.PageViews, name, account)
	}

	if !slices.Contains(deniedMetricsSet, "zoneUniquesTotal") {
		Metrics["zoneUniquesTotal"].RecordValueWithLabels(zt.Unique.Uniques, name, account)
	}
}

func addFirewallGroups(z *zoneResp, name string, account string, deniedMetricsSet []string) {
	// Nothing to do.
	if len(z.FirewallEventsAdaptiveGroups) == 0 {
		return
	}
	rulesMap := fetchFirewallRules(z.ZoneTag)
	if !slices.Contains(deniedMetricsSet, "zoneFirewallEventsCount") {
		for _, g := range z.FirewallEventsAdaptiveGroups {
			Metrics["zoneFirewallEventsCount"].RecordValueWithLabels(
				g.Count,
				name,
				account,
				g.Dimensions.Action,
				g.Dimensions.Source,
				normalizeRuleName(rulesMap[g.Dimensions.RuleID]),
				g.Dimensions.ClientRequestHTTPHost,
				g.Dimensions.ClientCountryName,
			)
		}
	}
}

func normalizeRuleName(initialText string) string {
	maxLength := 200
	nonSpaceName := strings.ReplaceAll(strings.ToLower(initialText), " ", "_")
	if len(nonSpaceName) > maxLength {
		return nonSpaceName[:maxLength]
	}
	return nonSpaceName
}

func addHealthCheckGroups(z *zoneResp, name string, account string, deniedMetricsSet []string) {
	if len(z.HealthCheckEventsAdaptiveGroups) == 0 {
		return
	}

	if !slices.Contains(deniedMetricsSet, "zoneHealthCheckEventsOriginCount") {
		for _, g := range z.HealthCheckEventsAdaptiveGroups {
			Metrics["zoneHealthCheckEventsOriginCount"].RecordValueWithLabels(
				g.Count,
				name,
				account,
				g.Dimensions.HealthStatus,
				g.Dimensions.OriginIP,
				g.Dimensions.Region,
				g.Dimensions.Fqdn,
			)
		}
	}
}

func addHTTPAdaptiveGroups(z *zoneResp, name string, account string, deniedMetricsSet []string) {
	if !slices.Contains(deniedMetricsSet, "zoneRequestOriginStatusCountryHost") {
		for _, g := range z.HTTPRequestsAdaptiveGroups {
			Metrics["zoneRequestsOriginStatusCountryHost"].RecordValueWithLabels(
				g.Count,
				name,
				account,
				strconv.Itoa(int(g.Dimensions.OriginResponseStatus)),
				g.Dimensions.ClientCountryName,
				g.Dimensions.ClientRequestHTTPHost,
			)
		}
	}
	if !slices.Contains(deniedMetricsSet, "zoneRequestStatusCountryHost") {
		for _, g := range z.HTTPRequestsEdgeCountryHost {
			Metrics["zoneRequestsStatusCountryHost"].RecordValueWithLabels(
				g.Count,
				name,
				account,
				strconv.Itoa(int(g.Dimensions.EdgeResponseStatus)),
				g.Dimensions.ClientCountryName,
				g.Dimensions.ClientRequestHTTPHost,
			)
		}
	}
}

func fetchLoadBalancerAnalytics(zones []cfzones.Zone, wg *sync.WaitGroup, deniedMetricsSet []string) {
	wg.Add(1)
	defer wg.Done()

	// None of the below referenced metrics are available in the free tier
	if viper.GetBool("free_tier") {
		return
	}

	zoneIDs := extractZoneIDs(zones)
	if len(zoneIDs) == 0 {
		return
	}

	l, err := fetchLoadBalancerTotals(zoneIDs)
	if err != nil {
		log.Error("failed to fetch load balancer analytics: ", err)
		return
	}
	for _, lb := range l.Viewer.Zones {
		name, account := findZoneAccountName(zones, lb.ZoneTag)
		lb := lb
		addLoadBalancingRequestsAdaptive(&lb, name, account, deniedMetricsSet)
		addLoadBalancingRequestsAdaptiveGroups(&lb, name, account, deniedMetricsSet)
	}
}

func addLoadBalancingRequestsAdaptiveGroups(z *lbResp, name string, account string, deniedMetricsSet []string) {
	if !slices.Contains(deniedMetricsSet, "poolRequestsTotal") {
		for _, g := range z.LoadBalancingRequestsAdaptiveGroups {
			Metrics["zonePoolRequestsTotal"].RecordValueWithLabels(
				g.Count,
				name,
				account,
				g.Dimensions.LbName,
				g.Dimensions.SelectedPoolName,
				g.Dimensions.SelectedOriginName,
			)
		}
	}
}

func addLoadBalancingRequestsAdaptive(z *lbResp, name string, account string, deniedMetricsSet []string) {
	if !slices.Contains(deniedMetricsSet, "poolHealthStatus") {
		for _, g := range z.LoadBalancingRequestsAdaptive {
			for _, p := range g.Pools {
				Metrics["zonePoolHealthStatus"].RecordValueWithLabels(
					p.Healthy,
					name,
					account,
					g.LbName,
					p.PoolName,
				)
			}
		}
	}
}

func fetchZeroTrustAnalyticsForAccount(account cfaccounts.Account, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	addCloudflareTunnelStatus(account)
}

func addCloudflareTunnelStatus(account cfaccounts.Account) {
	tunnels := fetchCloudflareTunnels(account)
	for _, t := range tunnels {
		Metrics["tunnelInfo"].RecordValueWithLabels(
			1,
			account.Name,
			t.ID,
			t.Name,
			string(t.TunType),
		)

		Metrics["tunnelHealthStatus"].RecordValueWithLabels(
			getCloudflareTunnelStatusValue(string(t.Status)),
			account.Name,
			t.ID,
		)

		// Each client/connector can open many connections to the Cloudflare edge,
		// we opt to not expose metrics for each individual connection. We do expose
		// an informational metric for each client/connector however.
		clients := fetchCloudflareTunnelConnectors(account, t.ID)
		for _, c := range clients {
			originIP := ""
			if len(c.Conns) > 0 {
				originIP = c.Conns[0].OriginIP
			}

			Metrics["tunnelConnectorInfo"].RecordValueWithLabels(
				1,
				account.Name,
				t.ID,
				c.ID,
				c.Version,
				c.Arch,
				originIP,
			)

			Metrics["tunnelConnectorActiveConnections"].RecordValueWithLabels(
				len(c.Conns),
				account.Name,
				t.ID,
				c.ID,
			)
		}
	}
}

// The status of the tunnel.
// Valid values are:
//   - inactive (tunnel has never been run)
//   - degraded (tunnel is active and able to serve traffic but in an unhealthy state)
//   - healthy (tunnel is active and able to serve traffic)
//   - down (tunnel can not serve traffic as it has no connections to the Cloudflare Edge).
func getCloudflareTunnelStatusValue(status string) uint8 {
	switch status {
	case "inactive":
		return 3
	case "degraded":
		return 2
	case "healthy":
		return 1
	case "down":
		return 0
	default:
		// Undefined status value returned by the API
		return 255
	}
}
