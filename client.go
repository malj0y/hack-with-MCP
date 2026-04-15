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

const h1BaseURL = "https://api.hackerone.com/v1"

type H1Client struct {
	username string
	token    string
	http     *http.Client
}

func newH1Client(username, token string) *H1Client {
	return &H1Client{
		username: username,
		token:    token,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

// get makes a single authenticated GET request with retry on 429.
func (c *H1Client) get(ctx context.Context, path string, params url.Values) (map[string]any, error) {
	u := h1BaseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(c.username, c.token)
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
			return nil, fmt.Errorf("H1 API %s → HTTP %d: %s", path, resp.StatusCode, string(body))
		}

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("JSON decode: %w", err)
		}
		return result, nil
	}
	return nil, fmt.Errorf("H1 API %s failed after 3 attempts (rate limited)", path)
}

// post makes an authenticated POST request.
func (c *H1Client) post(ctx context.Context, path string, payload map[string]any) (map[string]any, error) {
	import_body, _ := json.Marshal(payload)
	u := h1BaseURL + path

	req, err := http.NewRequestWithContext(ctx, "POST", u,
		io.NopCloser(bytesReader(import_body)))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(import_body))

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("H1 API POST %s → HTTP %d: %s", path, resp.StatusCode, string(body))
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("JSON decode: %w", err)
	}
	return result, nil
}

// fetchAllPages paginates through all pages of a GET endpoint and returns all data items.
func (c *H1Client) fetchAllPages(ctx context.Context, path string, extraParams url.Values) ([]map[string]any, error) {
	var all []map[string]any
	page := 1

	for {
		params := url.Values{}
		for k, vs := range extraParams {
			for _, v := range vs {
				params.Add(k, v)
			}
		}
		params.Set("page[number]", strconv.Itoa(page))
		params.Set("page[size]", "100")

		result, err := c.get(ctx, path, params)
		if err != nil {
			return nil, err
		}

		data, _ := result["data"].([]any)
		if len(data) == 0 {
			break
		}
		for _, item := range data {
			if m, ok := item.(map[string]any); ok {
				all = append(all, m)
			}
		}

		links, _ := result["links"].(map[string]any)
		if links["next"] == nil {
			break
		}
		page++
	}
	return all, nil
}

// --- Helpers for navigating H1's nested JSON structure ---

func attrs(obj map[string]any) map[string]any {
	a, _ := obj["attributes"].(map[string]any)
	return a
}

func rels(obj map[string]any) map[string]any {
	r, _ := obj["relationships"].(map[string]any)
	return r
}

func relData(obj map[string]any, key string) map[string]any {
	r := rels(obj)
	rel, _ := r[key].(map[string]any)
	d, _ := rel["data"].(map[string]any)
	return d
}

func relDataList(obj map[string]any, key string) []any {
	r := rels(obj)
	rel, _ := r[key].(map[string]any)
	d, _ := rel["data"].([]any)
	return d
}

func str(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func flt(m map[string]any, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

func boolVal(m map[string]any, key string) bool {
	v, _ := m[key].(bool)
	return v
}

// bytesReader wraps a []byte as an io.Reader.
func bytesReader(b []byte) io.Reader {
	return &bytesReaderImpl{b: b, pos: 0}
}

type bytesReaderImpl struct {
	b   []byte
	pos int
}

func (r *bytesReaderImpl) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n = copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}
