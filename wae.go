package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const waeAPIBase = "https://api.cloudflare.com/client/v4/accounts"

// WAEClient queries the Workers Analytics Engine SQL API.
type WAEClient struct {
	httpClient *http.Client
}

// WAEResponse is the JSON response from the WAE SQL API.
// This is NOT the standard Cloudflare v4 API envelope.
type WAEResponse struct {
	Meta []WAEColumnMeta          `json:"meta"`
	Data []map[string]interface{} `json:"data"`
	Rows int                      `json:"rows"`
}

type WAEColumnMeta struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func NewWAEClient(httpClient *http.Client) *WAEClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &WAEClient{httpClient: httpClient}
}

// Query executes a SQL query against the WAE API for the given account.
func (w *WAEClient) Query(ctx context.Context, accountID, query string) (*WAEResponse, error) {
	url := fmt.Sprintf("%s/%s/analytics_engine/sql", waeAPIBase, accountID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("creating WAE request: %w", err)
	}

	log.Debugf("WAE query (account=%s): %s", accountID, query)

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing WAE query: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading WAE response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WAE query failed (HTTP %d): %s", resp.StatusCode, body)
	}

	var result WAEResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing WAE response: %w", err)
	}

	return &result, nil
}
