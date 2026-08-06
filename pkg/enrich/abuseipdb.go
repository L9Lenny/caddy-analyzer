package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AbuseIPDB is an Enricher backed by the AbuseIPDB API v2.
// API key: set ABUSEIPDB_KEY env var. Free tier: 1000 checks/day.
type AbuseIPDB struct {
	apiKey string
	client *http.Client
}

// NewAbuseIPDB creates an AbuseIPDB enricher. apiKey must be non-empty.
func NewAbuseIPDB(apiKey string) *AbuseIPDB {
	return &AbuseIPDB{
		apiKey: apiKey,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *AbuseIPDB) Name() string { return "abuseipdb" }

func (a *AbuseIPDB) Lookup(ip string) (*Reputation, error) {
	if a.apiKey == "" {
		return nil, fmt.Errorf("abuseipdb: API key not set")
	}
	if IsPrivateOrLoopback(ip) {
		return &Reputation{
			IP:        ip,
			Source:    a.Name(),
			Score:     0,
			FetchedAt: time.Now(),
		}, nil
	}

	u, err := url.Parse("https://api.abuseipdb.com/api/v2/check")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", a.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb: HTTP %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			IPAddress            string   `json:"ipAddress"`
			IsPublic             bool     `json:"isPublic"`
			AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
			CountryCode          string   `json:"countryCode"`
			ISP                  string   `json:"isp"`
			UsageType            string   `json:"usageType"`
			Domain               string   `json:"domain"`
			TotalReports         int      `json:"totalReports"`
			NumDistinctUsers     int      `json:"numDistinctUsers"`
			Hostnames            []string `json:"hostnames"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("abuseipdb decode: %w", err)
	}

	d := body.Data
	return &Reputation{
		IP:        ip,
		Source:    a.Name(),
		Score:     d.AbuseConfidenceScore,
		Malicious: d.AbuseConfidenceScore >= 70,
		Country:   d.CountryCode,
		ISP:       d.ISP,
		UsageType: d.UsageType,
		Reports:   d.TotalReports,
		FetchedAt: time.Now(),
	}, nil
}
