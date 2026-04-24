package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const intigritiBaseURL = "https://api.intigriti.com/external/researcher/v1"

type IntigritiClient struct {
	token string
	http  *http.Client
}

func newIntigritiClient(token string) *IntigritiClient {
	return &IntigritiClient{
		token: token,
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *IntigritiClient) do(ctx context.Context, path string, params url.Values) ([]byte, error) {
	u := intigritiBaseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == 429 {
			time.Sleep(60 * time.Second)
			continue
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("Intigriti API %s → HTTP %d: %s", path, resp.StatusCode, string(body))
		}
		return body, nil
	}
	return nil, fmt.Errorf("Intigriti API %s failed after 3 attempts (rate limited)", path)
}

// get fetches a single object endpoint.
func (c *IntigritiClient) get(ctx context.Context, path string, params url.Values) (map[string]any, error) {
	body, err := c.do(ctx, path, params)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("JSON decode: %w", err)
	}
	return result, nil
}

// getList fetches all pages from a list endpoint using offset-based pagination.
// Handles both bare array responses and wrapped {records:[...]} responses.
func (c *IntigritiClient) getList(ctx context.Context, path string, extraParams url.Values) ([]map[string]any, error) {
	var all []map[string]any
	const pageSize = 50
	offset := 0

	for {
		params := url.Values{}
		for k, vs := range extraParams {
			for _, v := range vs {
				params.Add(k, v)
			}
		}
		params.Set("limit", strconv.Itoa(pageSize))
		params.Set("offset", strconv.Itoa(offset))

		body, err := c.do(ctx, path, params)
		if err != nil {
			return nil, err
		}

		items, err := parseIntigritiList(body)
		if err != nil {
			return nil, err
		}

		all = append(all, items...)
		if len(items) < pageSize {
			break
		}
		offset += pageSize
	}
	return all, nil
}

// parseIntigritiList handles both bare array and {records:[...]} wrapped responses.
func parseIntigritiList(body []byte) ([]map[string]any, error) {
	// Try bare array first
	var items []map[string]any
	if err := json.Unmarshal(body, &items); err == nil {
		return items, nil
	}

	// Try wrapped response
	var wrapped struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("unexpected Intigriti response format: %w", err)
	}
	return wrapped.Records, nil
}

// --- Helpers for Intigriti's nested value objects ---

// istr extracts a string from a field directly.
func istr(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// ival extracts the "value" string from a nested {id, value} object.
func ival(m map[string]any, key string) string {
	obj, _ := m[key].(map[string]any)
	v, _ := obj["value"].(string)
	return v
}

// ibounty extracts bounty value and currency from {value, currency} object.
func ibounty(m map[string]any, key string) (float64, string) {
	obj, _ := m[key].(map[string]any)
	if obj == nil {
		return 0, ""
	}
	v, _ := obj["value"].(float64)
	c, _ := obj["currency"].(string)
	return v, c
}
