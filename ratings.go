package aihorde

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DatasetGetResponse represents the response structure for the GetDatasets endpoint.
// Based on previous definition in types.go. Adjust if the actual API differs.
type DatasetGetResponse struct {
	ID string `json:"id"`
}

type AIHordeRatings struct {
	defaultToken string
	apiRoute     string
	clientAgent  string
}

type AIHordeRatingsOption func(*AIHordeRatings)

func NewAIHordeRatings(options ...AIHordeRatingsOption) *AIHordeRatings {
	r := &AIHordeRatings{
		apiRoute:    "https://ratings.aihorde.net/api/v1", // Default ratings API route
		clientAgent: "unknown",                            // Default agent
	}

	for _, opt := range options {
		opt(r)
	}

	return r
}

func WithRatingsDefaultToken(token string) AIHordeRatingsOption {
	return func(r *AIHordeRatings) {
		r.defaultToken = token
	}
}

func WithRatingsAPIRoute(route string) AIHordeRatingsOption {
	return func(r *AIHordeRatings) {
		r.apiRoute = route
	}
}

func WithRatingsClientAgent(agent string) AIHordeRatingsOption {
	return func(r *AIHordeRatings) {
		r.clientAgent = agent
	}
}

// request handles making HTTP requests to the AI Horde Ratings API.
// Note: This uses the shared RequestOption type defined in horde.go
func (r *AIHordeRatings) request(method, path string, options ...RequestOption) (*http.Response, error) {
	opts := &requestOptions{} // Uses requestOptions from horde.go
	for _, opt := range options {
		opt(opts)
	}

	// Prepend base API route if path doesn't already start with it
	reqURL := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		reqURL = r.apiRoute + path
	}

	// Add query parameters if provided
	if len(opts.queryParams) > 0 {
		q := url.Values{}
		for k, v := range opts.queryParams {
			q.Add(k, v)
		}
		reqURL += "?" + q.Encode()
	}

	var bodyReader io.Reader
	var bodyBytesForError []byte // Store marshalled body only for error reporting if needed
	if opts.body != nil {
		bodyBytes, err := json.Marshal(opts.body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyBytesForError = bodyBytes // Keep a copy for potential error reporting
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Client-Agent", r.clientAgent)
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(bodyBytesForError)) // Use length from marshalled bytes
	}

	// Use specific token if provided, otherwise default
	tokenToUse := r.defaultToken
	if opts.token != "" {
		tokenToUse = opts.token
	}
	if tokenToUse != "" {
		req.Header.Set("apikey", tokenToUse)
	}

	if len(opts.fields) > 0 {
		req.Header.Set("X-Fields", strings.Join(opts.fields, ","))
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		respBodyBytes, _ := io.ReadAll(resp.Body)

		// Try parsing as RequestValidationError first (assuming shared error types)
		var validationErr RequestValidationError
		if json.Unmarshal(respBodyBytes, &validationErr) == nil && validationErr.RC != "" {
			apiErr := &APIError{ // Use shared APIError type
				Status:       resp.StatusCode,
				Method:       method,
				URL:          reqURL,
				RequestBody:  bodyBytesForError, // Use the stored marshalled body
				ErrorMessage: ErrorMessages[validationErr.RC],
				ErrorCode:    validationErr.RC,
				Errors:       validationErr.Errors,
			}
			if apiErr.ErrorMessage == "" {
				apiErr.ErrorMessage = validationErr.Message
			}
			return nil, apiErr
		}

		// Try parsing as standard RequestError
		var errResp RequestError
		if json.Unmarshal(respBodyBytes, &errResp) == nil && errResp.RC != "" {
			apiErr := &APIError{ // Use shared APIError type
				Status:       resp.StatusCode,
				Method:       method,
				URL:          reqURL,
				RequestBody:  bodyBytesForError, // Use the stored marshalled body
				ErrorMessage: ErrorMessages[errResp.RC],
				ErrorCode:    errResp.RC,
			}
			if apiErr.ErrorMessage == "" {
				apiErr.ErrorMessage = errResp.Message
			}
			return nil, apiErr
		}

		// Fallback for unparseable errors
		return nil, fmt.Errorf("non-2xx response: %d %s, Body: %s", resp.StatusCode, resp.Status, string(respBodyBytes))
	}

	return resp, nil
}

// GetDatasets retrieves available rating datasets.
// GET /datasets (Ratings API v1)
func (r *AIHordeRatings) GetDatasets(options ...GetDatasetsOption) ([]DatasetGetResponse, error) {
	opts := &getDatasetsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	// No token needed for this endpoint based on typical public data endpoints
	resp, err := r.request("GET", "/datasets", WithFields(opts.fields)) // Uses shared WithFields
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var datasets []DatasetGetResponse
	if err := json.NewDecoder(resp.Body).Decode(&datasets); err != nil {
		return nil, fmt.Errorf("failed to decode GetDatasets response: %w", err)
	}
	return datasets, nil
}

type GetDatasetsOption func(*getDatasetsOptions)

type getDatasetsOptions struct {
	fields []string
}

func WithGetDatasetsFields(fields []string) GetDatasetsOption {
	return func(o *getDatasetsOptions) {
		o.fields = fields
	}
}

// --- TODO: Add other Ratings API endpoints if needed ---
