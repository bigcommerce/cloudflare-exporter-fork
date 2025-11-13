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

func (m *Metric) MustRegister() {
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

func RecordMetricValueWithLabels[T float64 | int | int64 | uint | uint64](m Metric, value T, labels ...string) {
	switch m.Type {
	case "counter":
		m.collector.(*prometheus.CounterVec).WithLabelValues(labels...).Add(float64(value))
	case "gauge":
		m.collector.(*prometheus.GaugeVec).WithLabelValues(labels...).Set(float64(value))
	case "histogram":
		m.collector.(*prometheus.HistogramVec).WithLabelValues(labels...).Observe(float64(value))
	case "summary":
		m.collector.(*prometheus.SummaryVec).WithLabelValues(labels...).Observe(float64(value))
	default:
		panic(fmt.Sprintf("unknown metric type: %s", m.Type))
	}
}

type MetricName string

func (mn MetricName) String() string {
	return string(mn)
}

type MetricsSet map[MetricName]struct{}

func (ms MetricsSet) Has(mn MetricName) bool {
	_, exists := ms[mn]
	return exists
}

func (ms MetricsSet) Add(mn MetricName) {
	ms[mn] = struct{}{}
}

var NeMetricSet = map[string]Metric{
	"zoneRequestTotalMetricName": {
		Name:   "cloudflare_zone_requests_total",
		Help:   "Number of requests for zone",
		Labels: []string{"zone", "account"},
		Type:   "counter",
	},
	//{Name: "cloudflare_zone_requests_cached",
	//	Help:   "Number of cached requests for zone",
	//	Labels: []string{"zone", "account"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_requests_ssl_encrypted",
	//	Help:   "Number of encrypted requests for zone",
	//	Labels: []string{"zone", "account"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_requests_content_type",
	//	Help:   "Number of request for zone per content type",
	//	Labels: []string{"zone", "account", "content_type"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_requests_country",
	//	Help:   "Number of request for zone per country",
	//	Labels: []string{"zone", "account", "country", "region"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_requests_status",
	//	Help:   "Number of request for zone per HTTP status",
	//	Labels: []string{"zone", "account", "status"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_requests_browser_map_page_views_count",
	//	Help:   "Number of successful requests for HTML pages per zone",
	//	Labels: []string{"zone", "account", "family"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_requests_origin_status_country_host",
	//	Help:   "Count of not cached requests for zone per origin HTTP status per country per host",
	//	Labels: []string{"zone", "account", "status", "country", "host"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_requests_status_country_host",
	//	Help:   "Count of requests for zone per edge HTTP status per country per host",
	//	Labels: []string{"zone", "account", "status", "country", "host"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_bandwidth_total",
	//	Help:   "Total bandwidth per zone in bytes",
	//	Labels: []string{"zone", "account"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_bandwidth_cached",
	//	Help:   "Cached bandwidth per zone in bytes",
	//	Labels: []string{"zone", "account"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_bandwidth_ssl_encrypted",
	//	Help:   "Encrypted bandwidth per zone in bytes",
	//	Labels: []string{"zone", "account"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_bandwidth_content_type",
	//	Help:   "Bandwidth per zone per content type",
	//	Labels: []string{"zone", "account", "content_type"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_bandwidth_country",
	//	Help:   "Bandwidth per country per zone",
	//	Labels: []string{"zone", "account", "country", "region"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_threats_total",
	//	Help:   "Threats per zone",
	//	Labels: []string{"zone", "account"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_threats_country",
	//	Help:   "Threats per zone per country",
	//	Labels: []string{"zone", "account", "country", "region"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_threats_type",
	//	Help:   "Threats per zone per type",
	//	Labels: []string{"zone", "account", "type"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_pageviews_total",
	//	Help:   "Pageviews per zone",
	//	Labels: []string{"zone", "account"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_uniques_total",
	//	Help:   "Uniques per zone",
	//	Labels: []string{"zone", "account"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_colocation_visits",
	//	Help:   "Total visits per colocation",
	//	Labels: []string{"zone", "account", "colocation", "host"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_colocation_edge_response_bytes",
	//	Help:   "Edge response bytes per colocation",
	//	Labels: []string{"zone", "account", "colocation", "host"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_colocation_requests_total",
	//	Help:   "Total requests per colocation",
	//	Labels: []string{"zone", "account", "colocation", "host"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_firewall_events_count",
	//	Help:   "Count of Firewall events",
	//	Labels: []string{"zone", "account", "action", "source", "rule", "host", "country"},
	//	Type:   "counter"},
	//{Name: "cloudflare_zone_health_check_events_origin_count",
	//	Help:   "Number of Heath check events per region per origin",
	//	Labels: []string{"zone", "account", "health_status", "origin_ip", "region", "fqdn"},
	//	Type:   "counter"},
	//{Name: "cloudflare_worker_requests_count",
	//	Help:   "Number of requests sent to worker by script name",
	//	Labels: []string{"script_name", "account", "status"},
	//	Type:   "counter"},
	//{Name: "cloudflare_worker_errors_count",
	//	Help:   "Number of errors by script name",
	//	Labels: []string{"script_name", "account", "status"},
	//	Type:   "counter"},
	//{Name: "cloudflare_worker_cpu_time",
	//	Help:   "CPU time quantiles by script name",
	//	Labels: []string{"script_name", "account", "status", "quantile"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_worker_duration",
	//	Help:   "Duration quantiles by script name (GB*s)",
	//	Labels: []string{"script_name", "account", "status", "quantile"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_zone_pool_health_status",
	//	Help:   "Reports the health of a pool, 1 for healthy, 0 for unhealthy.",
	//	Labels: []string{"zone", "account", "load_balancer_name", "pool_name"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_pool_origin_health_status",
	//	Help:   "Reports the origin health of a pool, 1 for healthy, 0 for unhealthy.",
	//	Labels: []string{"account", "pool_name", "origin_name", "ip"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_zone_pool_requests_total",
	//	Help:   "Requests per pool",
	//	Labels: []string{"zone", "account", "load_balancer_name", "pool_name", "origin_name"},
	//	Type:   "counter"},
	//{Name: "cloudflare_logpush_failed_jobs_account_count",
	//	Help:   "Number of failed logpush jobs on the account level",
	//	Labels: []string{"account", "destination", "job_id", "final"},
	//	Type:   "counter"},
	//{Name: "cloudflare_logpush_failed_jobs_zone_count",
	//	Help:   "Number of failed logpush jobs on the zone level",
	//	Labels: []string{"destination", "job_id", "final"},
	//	Type:   "counter"},
	//{Name: "cloudflare_r2_storage_total_bytes",
	//	Help:   "Total storage used by R2",
	//	Labels: []string{"account"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_r2_storage_bytes",
	//	Help:   "Storage used by R2",
	//	Labels: []string{"account", "bucket"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_r2_operation_count",
	//	Help:   "Number of operations performed by R2",
	//	Labels: []string{"account", "bucket", "operation"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_tunnel_info",
	//	Help:   "Reports Cloudflare Tunnel details",
	//	Labels: []string{"account", "tunnel_id", "tunnel_name", "tunnel_type"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_tunnel_health_status",
	//	Help:   "Reports the health of a Cloudflare Tunnel, 0 for unhealthy, 1 for healthy, 2 for degraded, 3 for inactive",
	//	Labels: []string{"account", "tunnel_id"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_tunnel_connector_info",
	//	Help:   "Reports Cloudflare Tunnel connector details",
	//	Labels: []string{"account", "tunnel_id", "client_id", "version", "arch", "origin_ip"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_tunnel_connector_active_connections",
	//	Help:   "Reports number of active connections for a Cloudflare Tunnel connector",
	//	Labels: []string{"account", "tunnel_id", "client_id"},
	//	Type:   "gauge"},
	//{Name: "cloudflare_dns_firewall_query_count",
	//	Help:   "DNS Firewall query count by query type and response code",
	//	Labels: []string{"account_id", "account_name", "dns_firewall_id", "query_type", "response_code"},
	//	Type:   "gauge"},
}

func mustRegisterMetrics(deniedMetrics []string) {
	for _, metric := range NeMetricSet {
		if !slices.Contains(deniedMetrics, metric.Name) {
			metric.MustRegister()
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
			RecordMetricValueWithLabels(NeMetricSet["cloudflare_pool_origin_health_status"], healthy, account.Name, pool.Name, o.Name, o.Address)
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
			workerRequests.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "status": w.Dimensions.Status}).Add(float64(w.Sum.Requests))
			workerErrors.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "status": w.Dimensions.Status}).Add(float64(w.Sum.Errors))
			workerCPUTime.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "status": w.Dimensions.Status, "quantile": "P50"}).Set(float64(w.Quantiles.CPUTimeP50))
			workerCPUTime.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "status": w.Dimensions.Status, "quantile": "P75"}).Set(float64(w.Quantiles.CPUTimeP75))
			workerCPUTime.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "status": w.Dimensions.Status, "quantile": "P99"}).Set(float64(w.Quantiles.CPUTimeP99))
			workerCPUTime.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "status": w.Dimensions.Status, "quantile": "P999"}).Set(float64(w.Quantiles.CPUTimeP999))
			workerDuration.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "status": w.Dimensions.Status, "quantile": "P50"}).Set(float64(w.Quantiles.DurationP50))
			workerDuration.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "status": w.Dimensions.Status, "quantile": "P75"}).Set(float64(w.Quantiles.DurationP75))
			workerDuration.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "status": w.Dimensions.Status, "quantile": "P99"}).Set(float64(w.Quantiles.DurationP99))
			workerDuration.With(prometheus.Labels{"script_name": w.Dimensions.ScriptName, "account": accountName, "status": w.Dimensions.Status, "quantile": "P999"}).Set(float64(w.Quantiles.DurationP999))
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
			logpushFailedJobsAccount.With(prometheus.Labels{"account": account.ID,
				"destination": LogpushHealthAdaptiveGroup.Dimensions.DestinationType,
				"job_id":      strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.JobID),
				"final":       strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.Final)}).Add(float64(LogpushHealthAdaptiveGroup.Count))
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
			r2Storage.With(prometheus.Labels{"account": account.Name, "bucket": bucket.Dimensions.BucketName}).Set(float64(bucket.Max.PayloadSize))
		}
		for _, operation := range acc.R2StorageOperations {
			r2Operation.With(prometheus.Labels{"account": account.Name, "bucket": operation.Dimensions.BucketName, "operation": operation.Dimensions.Action}).Set(float64(operation.Sum.Requests))
		}
		r2StorageTotal.With(prometheus.Labels{"account": account.Name}).Set(float64(totalStorage))
	}
}

func fetchLogpushAnalyticsForZone(zones []cfzones.Zone, wg *sync.WaitGroup, _ MetricsSet) {
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
			logpushFailedJobsZone.With(prometheus.Labels{"destination": LogpushHealthAdaptiveGroup.Dimensions.DestinationType,
				"job_id": strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.JobID),
				"final":  strconv.Itoa(LogpushHealthAdaptiveGroup.Dimensions.Final)}).Add(float64(LogpushHealthAdaptiveGroup.Count))
		}
	}
}

func fetchDNSFirewallAnalytics(account cfaccounts.Account, wg *sync.WaitGroup, deniedMetricsSet MetricsSet) {
	wg.Add(1)
	defer wg.Done()

	r, err := fetchDNSFirewallTotals(account.ID)
	if err != nil {
		return
	}

	for _, a := range r.Viewer.Accounts {
		for _, d := range a.DNSFirewallAnalyticsAdaptiveGroups {
			if !deniedMetricsSet.Has(dnsFirewallQueryCountMetricName) {
				dnsFirewallQueryCount.WithLabelValues(
					account.ID,
					account.Name,
					d.Dimensions.ClusterTag,
					d.Dimensions.QueryType,
					d.Dimensions.ResponseCode,
				).Set(float64(d.Count))
			}
		}
	}
}

func fetchZoneColocationAnalytics(zones []cfzones.Zone, wg *sync.WaitGroup, deniedMetricsSet MetricsSet) {
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
			if !deniedMetricsSet.Has(zoneColocationVisitsMetricName) {
				zoneColocationVisits.With(prometheus.Labels{"zone": name, "account": account, "colocation": c.Dimensions.ColoCode, "host": c.Dimensions.Host}).Add(float64(c.Sum.Visits))
			}
			if !deniedMetricsSet.Has(zoneColocationEdgeResponseBytesMetricName) {
				zoneColocationEdgeResponseBytes.With(prometheus.Labels{"zone": name, "account": account, "colocation": c.Dimensions.ColoCode, "host": c.Dimensions.Host}).Add(float64(c.Sum.EdgeResponseBytes))
			}
			if !deniedMetricsSet.Has(zoneColocationRequestsTotalMetricName) {
				zoneColocationRequestsTotal.With(prometheus.Labels{"zone": name, "account": account, "colocation": c.Dimensions.ColoCode, "host": c.Dimensions.Host}).Add(float64(c.Count))
			}
		}
	}
}

func fetchZoneAnalytics(zones []cfzones.Zone, wg *sync.WaitGroup, deniedMetricsSet MetricsSet) {
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

func addHTTPGroups(z *zoneResp, name string, account string, deniedMetricsSet MetricsSet) {
	// Nothing to do.
	if len(z.HTTP1mGroups) == 0 {
		return
	}

	zt := z.HTTP1mGroups[0]

	if !deniedMetricsSet.Has(zoneRequestTotalMetricName) {
		zoneRequestTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.Requests))
	}
	if !deniedMetricsSet.Has(zoneRequestCachedMetricName) {
		zoneRequestCached.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.CachedRequests))
	}
	if !deniedMetricsSet.Has(zoneRequestSSLEncryptedMetricName) {
		zoneRequestSSLEncrypted.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.EncryptedRequests))
	}

	for _, ct := range zt.Sum.ContentType {
		if !deniedMetricsSet.Has(zoneRequestContentTypeMetricName) {
			zoneRequestContentType.With(prometheus.Labels{"zone": name, "account": account, "content_type": ct.EdgeResponseContentType}).Add(float64(ct.Requests))
		}
		if !deniedMetricsSet.Has(zoneBandwidthContentTypeMetricName) {
			zoneBandwidthContentType.With(prometheus.Labels{"zone": name, "account": account, "content_type": ct.EdgeResponseContentType}).Add(float64(ct.Bytes))
		}
	}

	for _, country := range zt.Sum.Country {
		c := countries.ByName(country.ClientCountryName)
		region := c.Info().Region.Info().Name

		if !deniedMetricsSet.Has(zoneRequestCountryMetricName) {
			zoneRequestCountry.With(prometheus.Labels{"zone": name, "account": account, "country": country.ClientCountryName, "region": region}).Add(float64(country.Requests))
		}
		if !deniedMetricsSet.Has(zoneBandwidthCountryMetricName) {
			zoneBandwidthCountry.With(prometheus.Labels{"zone": name, "account": account, "country": country.ClientCountryName, "region": region}).Add(float64(country.Bytes))
		}
		if !deniedMetricsSet.Has(zoneThreatsCountryMetricName) {
			zoneThreatsCountry.With(prometheus.Labels{"zone": name, "account": account, "country": country.ClientCountryName, "region": region}).Add(float64(country.Threats))
		}
	}

	if !deniedMetricsSet.Has(zoneRequestHTTPStatusMetricName) {
		for _, status := range zt.Sum.ResponseStatus {
			zoneRequestHTTPStatus.With(prometheus.Labels{"zone": name, "account": account, "status": strconv.Itoa(status.EdgeResponseStatus)}).Add(float64(status.Requests))
		}
	}

	if !deniedMetricsSet.Has(zoneRequestBrowserMapMetricName) {
		for _, browser := range zt.Sum.BrowserMap {
			zoneRequestBrowserMap.With(prometheus.Labels{"zone": name, "account": account, "family": browser.UaBrowserFamily}).Add(float64(browser.PageViews))
		}
	}

	if !deniedMetricsSet.Has(zoneBandwidthTotalMetricName) {
		zoneBandwidthTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.Bytes))
	}
	if !deniedMetricsSet.Has(zoneBandwidthCachedMetricName) {
		zoneBandwidthCached.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.CachedBytes))
	}
	if !deniedMetricsSet.Has(zoneBandwidthSSLEncryptedMetricName) {
		zoneBandwidthSSLEncrypted.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.EncryptedBytes))
	}

	if !deniedMetricsSet.Has(zoneThreatsTotalMetricName) {
		zoneThreatsTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.Threats))
	}

	if !deniedMetricsSet.Has(zoneThreatsTypeMetricName) {
		for _, t := range zt.Sum.ThreatPathing {
			zoneThreatsType.With(prometheus.Labels{"zone": name, "account": account, "type": t.Name}).Add(float64(t.Requests))
		}
	}

	if !deniedMetricsSet.Has(zonePageviewsTotalMetricName) {
		zonePageviewsTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Sum.PageViews))
	}

	if !deniedMetricsSet.Has(zoneUniquesTotalMetricName) {
		// Uniques
		zoneUniquesTotal.With(prometheus.Labels{"zone": name, "account": account}).Add(float64(zt.Unique.Uniques))
	}
}

func addFirewallGroups(z *zoneResp, name string, account string, deniedMetricsSet MetricsSet) {
	// Nothing to do.
	if len(z.FirewallEventsAdaptiveGroups) == 0 {
		return
	}
	rulesMap := fetchFirewallRules(z.ZoneTag)
	if !deniedMetricsSet.Has(zoneFirewallEventsCountMetricName) {
		for _, g := range z.FirewallEventsAdaptiveGroups {
			zoneFirewallEventsCount.With(
				prometheus.Labels{
					"zone":    name,
					"account": account,
					"action":  g.Dimensions.Action,
					"source":  g.Dimensions.Source,
					"rule":    normalizeRuleName(rulesMap[g.Dimensions.RuleID]),
					"host":    g.Dimensions.ClientRequestHTTPHost,
					"country": g.Dimensions.ClientCountryName,
				}).Add(float64(g.Count))
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

func addHealthCheckGroups(z *zoneResp, name string, account string, deniedMetricsSet MetricsSet) {
	if len(z.HealthCheckEventsAdaptiveGroups) == 0 {
		return
	}

	if !deniedMetricsSet.Has(zoneHealthCheckEventsOriginCountMetricName) {
		for _, g := range z.HealthCheckEventsAdaptiveGroups {
			zoneHealthCheckEventsOriginCount.With(
				prometheus.Labels{
					"zone":          name,
					"account":       account,
					"health_status": g.Dimensions.HealthStatus,
					"origin_ip":     g.Dimensions.OriginIP,
					"region":        g.Dimensions.Region,
					"fqdn":          g.Dimensions.Fqdn,
				}).Add(float64(g.Count))
		}
	}
}

func addHTTPAdaptiveGroups(z *zoneResp, name string, account string, deniedMetricsSet MetricsSet) {
	if !deniedMetricsSet.Has(zoneRequestOriginStatusCountryHostMetricName) {
		for _, g := range z.HTTPRequestsAdaptiveGroups {
			zoneRequestOriginStatusCountryHost.With(
				prometheus.Labels{
					"zone":    name,
					"account": account,
					"status":  strconv.Itoa(int(g.Dimensions.OriginResponseStatus)),
					"country": g.Dimensions.ClientCountryName,
					"host":    g.Dimensions.ClientRequestHTTPHost,
				}).Add(float64(g.Count))
		}
	}
	if !deniedMetricsSet.Has(zoneRequestStatusCountryHostMetricName) {
		for _, g := range z.HTTPRequestsEdgeCountryHost {
			zoneRequestStatusCountryHost.With(
				prometheus.Labels{
					"zone":    name,
					"account": account,
					"status":  strconv.Itoa(int(g.Dimensions.EdgeResponseStatus)),
					"country": g.Dimensions.ClientCountryName,
					"host":    g.Dimensions.ClientRequestHTTPHost,
				}).Add(float64(g.Count))
		}
	}
}

func fetchLoadBalancerAnalytics(zones []cfzones.Zone, wg *sync.WaitGroup, deniedMetricsSet MetricsSet) {
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

func addLoadBalancingRequestsAdaptiveGroups(z *lbResp, name string, account string, deniedMetricsSet MetricsSet) {
	if !deniedMetricsSet.Has(poolRequestsTotalMetricName) {
		for _, g := range z.LoadBalancingRequestsAdaptiveGroups {
			poolRequestsTotal.With(
				prometheus.Labels{
					"zone":               name,
					"account":            account,
					"load_balancer_name": g.Dimensions.LbName,
					"pool_name":          g.Dimensions.SelectedPoolName,
					"origin_name":        g.Dimensions.SelectedOriginName,
				}).Add(float64(g.Count))
		}
	}
}

func addLoadBalancingRequestsAdaptive(z *lbResp, name string, account string, deniedMetricsSet MetricsSet) {
	if !deniedMetricsSet.Has(poolHealthStatusMetricName) {
		for _, g := range z.LoadBalancingRequestsAdaptive {
			for _, p := range g.Pools {
				poolHealthStatus.With(
					prometheus.Labels{
						"zone":               name,
						"account":            account,
						"load_balancer_name": g.LbName,
						"pool_name":          p.PoolName,
					}).Set(float64(p.Healthy))
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
		tunnelInfo.With(
			prometheus.Labels{
				"account":     account.Name,
				"tunnel_id":   t.ID,
				"tunnel_name": t.Name,
				"tunnel_type": string(t.TunType),
			}).Set(float64(1))

		tunnelHealthStatus.With(
			prometheus.Labels{
				"account":   account.Name,
				"tunnel_id": t.ID,
			}).Set(float64(getCloudflareTunnelStatusValue(string(t.Status))))

		// Each client/connector can open many connections to the Cloudflare edge,
		// we opt to not expose metrics for each individual connection. We do expose
		// an informational metric for each client/connector however.
		clients := fetchCloudflareTunnelConnectors(account, t.ID)
		for _, c := range clients {
			originIP := ""
			if len(c.Conns) > 0 {
				originIP = c.Conns[0].OriginIP
			}

			tunnelConnectorInfo.With(
				prometheus.Labels{
					"account":   account.Name,
					"tunnel_id": t.ID,
					"client_id": c.ID,
					"version":   c.Version,
					"arch":      c.Arch,
					"origin_ip": originIP,
				}).Set(float64(1))

			tunnelConnectorActiveConnections.With(
				prometheus.Labels{
					"account":   account.Name,
					"tunnel_id": t.ID,
					"client_id": c.ID,
				}).Set(float64(len(c.Conns)))
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
