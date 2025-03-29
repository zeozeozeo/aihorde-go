package aihorde

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type AIHorde struct {
	defaultToken string
	apiRoute     string
	version      string
	clientAgent  string
	Ratings      *AIHordeRatings
}

type AIHordeOption func(*AIHorde)

func NewAIHorde(options ...AIHordeOption) *AIHorde {
	h := &AIHorde{
		apiRoute:    "https://aihorde.net/api", // Base path from swagger
		version:     "Unknown",                 // TODO: Consider setting dynamically or removing if unused
		clientAgent: "@zeozeozeo/aihorde-go:Version_Unknown:github.com/zeozeozeo/aihorde-go/issues",
	}

	for _, opt := range options {
		opt(h)
	}

	// Initialize Ratings client if needed (assuming it exists and is compatible)
	// Check if NewAIHordeRatings and its options are defined elsewhere
	/*
		h.Ratings = NewAIHordeRatings(
			WithRatingsDefaultToken(h.defaultToken),
			WithRatingsAPIRoute("https://ratings.aihorde.net/api/v1"), // Example, adjust if needed
			WithRatingsClientAgent(h.clientAgent),
		)
	*/

	return h
}

func WithDefaultToken(token string) AIHordeOption {
	return func(h *AIHorde) {
		h.defaultToken = token
	}
}

func WithAPIRoute(route string) AIHordeOption {
	return func(h *AIHorde) {
		h.apiRoute = route
	}
}

func WithClientAgent(agent string) AIHordeOption {
	return func(h *AIHorde) {
		h.clientAgent = agent
	}
}

// APIError represents an error returned by the AI Horde API.
type APIError struct {
	Status       int
	Method       string
	URL          string
	RequestBody  []byte
	ErrorMessage string
	ErrorCode    string
	Errors       map[string]string
	// Warnings and Metadata might be part of successful responses, not errors.
	// Consider moving them or handling them differently based on response structure.
	// Warnings     []RequestSingleWarningCode
	// Metadata     map[GenerationMetadataType]GenerationMetadataValue
}

func (e *APIError) Error() string {
	errorDetails := ""
	if len(e.Errors) > 0 {
		var errs []string
		for k, v := range e.Errors {
			errs = append(errs, fmt.Sprintf("%s: %s", k, v))
		}
		errorDetails = fmt.Sprintf(" (Details: %s)", strings.Join(errs, "; "))
	}
	return fmt.Sprintf("%s %s: %d %s (code: %s)%s", e.Method, e.URL, e.Status, e.ErrorMessage, e.ErrorCode, errorDetails)
}

// request handles making HTTP requests to the AI Horde API.
func (h *AIHorde) request(method, path string, options ...RequestOption) (*http.Response, error) {
	opts := &requestOptions{}
	for _, opt := range options {
		opt(opts)
	}

	// Prepend base API route if path doesn't already start with it
	reqURL := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		reqURL = h.apiRoute + path
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
	var bodyBytes []byte // Store body bytes for error reporting
	if opts.body != nil {
		var err error
		bodyBytes, err = json.Marshal(opts.body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Client-Agent", h.clientAgent)
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(bodyBytes))
	}

	// Use specific token if provided, otherwise default
	tokenToUse := h.defaultToken
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

		// Try parsing as RequestValidationError first
		var validationErr RequestValidationError
		if json.Unmarshal(respBodyBytes, &validationErr) == nil && validationErr.RC != "" {
			apiErr := &APIError{
				Status:       resp.StatusCode,
				Method:       method,
				URL:          reqURL,
				RequestBody:  bodyBytes, // Use marshalled body bytes
				ErrorMessage: ErrorMessages[validationErr.RC],
				ErrorCode:    validationErr.RC,
				Errors:       validationErr.Errors,
			}
			if apiErr.ErrorMessage == "" {
				apiErr.ErrorMessage = validationErr.Message // Fallback to message if RC not in map
			}
			return nil, apiErr
		}

		// Try parsing as standard RequestError
		var errResp RequestError
		if json.Unmarshal(respBodyBytes, &errResp) == nil && errResp.RC != "" {
			apiErr := &APIError{
				Status:       resp.StatusCode,
				Method:       method,
				URL:          reqURL,
				RequestBody:  bodyBytes, // Use marshalled body bytes
				ErrorMessage: ErrorMessages[errResp.RC],
				ErrorCode:    errResp.RC,
			}
			if apiErr.ErrorMessage == "" {
				apiErr.ErrorMessage = errResp.Message // Fallback to message if RC not in map
			}
			return nil, apiErr
		}

		// Fallback for unparseable errors
		return nil, fmt.Errorf("non-2xx response: %d %s, Body: %s", resp.StatusCode, resp.Status, string(respBodyBytes))
	}

	return resp, nil
}

type RequestOption func(*requestOptions)

type requestOptions struct {
	token       string
	fields      []string
	body        interface{}
	queryParams map[string]string
}

// WithToken sets the API key for a specific request.
func WithToken(token string) RequestOption {
	return func(o *requestOptions) {
		o.token = token
	}
}

// WithFields sets the X-Fields header for sparse fieldsets.
func WithFields(fields []string) RequestOption {
	return func(o *requestOptions) {
		o.fields = fields
	}
}

// WithBody sets the JSON request body.
func WithBody(body interface{}) RequestOption {
	return func(o *requestOptions) {
		o.body = body
	}
}

// WithQueryParam adds a query parameter to the request URL.
func WithQueryParam(key, value string) RequestOption {
	return func(o *requestOptions) {
		if o.queryParams == nil {
			o.queryParams = make(map[string]string)
		}
		o.queryParams[key] = value
	}
}

// --- User Endpoints ---

// FindUser retrieves user details based on their API key.
// GET /v2/find_user
func (h *AIHorde) FindUser(options ...FindUserOption) (*UserDetails, error) {
	opts := &findUserOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}

	// Token is required and passed via header in request()
	resp, err := h.request("GET", "/v2/find_user", WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user UserDetails
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode FindUser response: %w", err)
	}
	return &user, nil
}

type FindUserOption func(*findUserOptions)
type findUserOptions struct {
	token  string // API key of the user to find (required)
	fields []string
}

func WithFindUserToken(token string) FindUserOption {
	return func(o *findUserOptions) {
		o.token = token
	}
}
func WithFindUserFields(fields []string) FindUserOption {
	return func(o *findUserOptions) {
		o.fields = fields
	}
}

// GetUserDetails retrieves details and statistics about a specific user by ID.
// GET /v2/users/{user_id}
func (h *AIHorde) GetUserDetails(userID int, options ...GetUserDetailsOption) (*UserDetails, error) {
	opts := &getUserDetailsOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/users/%d", userID)
	// Token is optional (for privileged info)
	resp, err := h.request("GET", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user UserDetails
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode GetUserDetails response: %w", err)
	}
	return &user, nil
}

type GetUserDetailsOption func(*getUserDetailsOptions)
type getUserDetailsOptions struct {
	token  string // Optional: Admin, Mod, or Owner API key for privileged info
	fields []string
}

func WithGetUserDetailsToken(token string) GetUserDetailsOption {
	return func(o *getUserDetailsOptions) {
		o.token = token
	}
}
func WithGetUserDetailsFields(fields []string) GetUserDetailsOption {
	return func(o *getUserDetailsOptions) {
		o.fields = fields
	}
}

// ModifyUser updates a user's details (Admin only).
// PUT /v2/users/{user_id}
func (h *AIHorde) ModifyUser(userID int, input ModifyUserInput, options ...ModifyUserOption) (*ModifyUser, error) {
	opts := &modifyUserOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Admin token is required
	if opts.token == "" {
		return nil, fmt.Errorf("admin API key is required for ModifyUser")
	}

	path := fmt.Sprintf("/v2/users/%d", userID)
	resp, err := h.request("PUT", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ModifyUser
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ModifyUser response: %w", err)
	}
	return &result, nil
}

type ModifyUserOption func(*modifyUserOptions)
type modifyUserOptions struct {
	token  string // Required: Admin API key
	fields []string
}

func WithModifyUserToken(token string) ModifyUserOption {
	return func(o *modifyUserOptions) {
		o.token = token
	}
}
func WithModifyUserFields(fields []string) ModifyUserOption {
	return func(o *modifyUserOptions) {
		o.fields = fields
	}
}

// GetUsers retrieves a list of all registered users.
// GET /v2/users
func (h *AIHorde) GetUsers(options ...GetUsersOption) ([]UserDetails, error) {
	opts := &getUsersOptions{
		page: 1,
		sort: SortKudos, // Default sort
	}
	for _, opt := range options {
		opt(opts)
	}

	requestOptions := []RequestOption{WithFields(opts.fields)}
	requestOptions = append(requestOptions, WithQueryParam("page", strconv.Itoa(opts.page)))
	requestOptions = append(requestOptions, WithQueryParam("sort", string(opts.sort)))

	resp, err := h.request("GET", "/v2/users", requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// The endpoint returns a single UserDetails object per page according to spec, not an array?
	// Let's assume it returns an array based on the function name and common practice.
	// If it truly returns one, the caller needs to handle pagination.
	var users []UserDetails
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		// Handle potential single object response if array fails
		// Re-read attempt might be needed depending on http client behavior after failed decode
		// For simplicity, just return the original error for now.
		return nil, fmt.Errorf("failed to decode GetUsers response: %w", err)
	}
	return users, nil
}

type GetUsersOption func(*getUsersOptions)
type getUsersOptions struct {
	page   int
	sort   SortType
	fields []string
}

func WithUsersPage(page int) GetUsersOption {
	return func(o *getUsersOptions) {
		if page > 0 {
			o.page = page
		}
	}
}
func WithUsersSort(sort SortType) GetUsersOption {
	return func(o *getUsersOptions) {
		o.sort = sort
	}
}
func WithUsersFields(fields []string) GetUsersOption {
	return func(o *getUsersOptions) {
		o.fields = fields
	}
}

// --- Generation Endpoints ---

// PostAsyncImageGenerate initiates an asynchronous request to generate images.
// POST /v2/generate/async
func (h *AIHorde) PostAsyncImageGenerate(input GenerationInputStable, options ...PostAsyncImageGenerateOption) (*RequestAsync, error) {
	opts := &postAsyncImageGenerateOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for PostAsyncImageGenerate")
	}

	resp, err := h.request("POST", "/v2/generate/async", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err // err might be *APIError
	}
	defer resp.Body.Close()

	var asyncReq RequestAsync
	if err := json.NewDecoder(resp.Body).Decode(&asyncReq); err != nil {
		return nil, fmt.Errorf("failed to decode PostAsyncImageGenerate response: %w", err)
	}
	return &asyncReq, nil
}

type PostAsyncImageGenerateOption func(*postAsyncImageGenerateOptions)
type postAsyncImageGenerateOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithPostAsyncImageGenerateToken(token string) PostAsyncImageGenerateOption {
	return func(o *postAsyncImageGenerateOptions) {
		o.token = token
	}
}
func WithPostAsyncImageGenerateFields(fields []string) PostAsyncImageGenerateOption {
	return func(o *postAsyncImageGenerateOptions) {
		o.fields = fields
	}
}

// GetAsyncGenerationCheck retrieves the status of an asynchronous generation request without images.
// GET /v2/generate/check/{id}
func (h *AIHorde) GetAsyncGenerationCheck(id string, options ...GetAsyncGenerationCheckOption) (*RequestStatusCheck, error) {
	opts := &getAsyncGenerationCheckOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/generate/check/%s", id)
	// No token needed for check endpoint
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status RequestStatusCheck
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode GetAsyncGenerationCheck response: %w", err)
	}
	return &status, nil
}

type GetAsyncGenerationCheckOption func(*getAsyncGenerationCheckOptions)
type getAsyncGenerationCheckOptions struct {
	fields []string
}

func WithGetAsyncGenerationCheckFields(fields []string) GetAsyncGenerationCheckOption {
	return func(o *getAsyncGenerationCheckOptions) {
		o.fields = fields
	}
}

// GetAsyncImageStatus retrieves the full status of an asynchronous image generation request, including images.
// GET /v2/generate/status/{id}
func (h *AIHorde) GetAsyncImageStatus(id string, options ...GetAsyncImageStatusOption) (*RequestStatusStable, error) {
	opts := &getAsyncImageStatusOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/generate/status/%s", id)
	// No token needed for status endpoint
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status RequestStatusStable
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode GetAsyncImageStatus response: %w", err)
	}
	return &status, nil
}

type GetAsyncImageStatusOption func(*getAsyncImageStatusOptions)
type getAsyncImageStatusOptions struct {
	fields []string
}

func WithGetAsyncImageStatusFields(fields []string) GetAsyncImageStatusOption {
	return func(o *getAsyncImageStatusOptions) {
		o.fields = fields
	}
}

// DeleteAsyncImageStatus cancels an unfinished image generation request.
// DELETE /v2/generate/status/{id}
func (h *AIHorde) DeleteAsyncImageStatus(id string, options ...DeleteAsyncImageStatusOption) (*RequestStatusStable, error) {
	opts := &deleteAsyncImageStatusOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/generate/status/%s", id)
	// No token needed for delete endpoint? Spec doesn't list one.
	resp, err := h.request("DELETE", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Response is RequestStatusStable according to spec
	var status RequestStatusStable
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteAsyncImageStatus response: %w", err)
	}
	return &status, nil
}

type DeleteAsyncImageStatusOption func(*deleteAsyncImageStatusOptions)
type deleteAsyncImageStatusOptions struct {
	fields []string
}

func WithDeleteAsyncImageStatusFields(fields []string) DeleteAsyncImageStatusOption {
	return func(o *deleteAsyncImageStatusOptions) {
		o.fields = fields
	}
}

// PostAsyncTextGenerate initiates an asynchronous request to generate text.
// POST /v2/generate/text/async
func (h *AIHorde) PostAsyncTextGenerate(input GenerationInputKobold, options ...PostAsyncTextGenerateOption) (*RequestAsync, error) {
	opts := &postAsyncTextGenerateOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for PostAsyncTextGenerate")
	}

	resp, err := h.request("POST", "/v2/generate/text/async", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var reqAsync RequestAsync
	if err := json.NewDecoder(resp.Body).Decode(&reqAsync); err != nil {
		return nil, fmt.Errorf("failed to decode PostAsyncTextGenerate response: %w", err)
	}
	return &reqAsync, nil
}

type PostAsyncTextGenerateOption func(*postAsyncTextGenerateOptions)
type postAsyncTextGenerateOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithPostAsyncTextGenerateToken(token string) PostAsyncTextGenerateOption {
	return func(o *postAsyncTextGenerateOptions) {
		o.token = token
	}
}
func WithPostAsyncTextGenerateFields(fields []string) PostAsyncTextGenerateOption {
	return func(o *postAsyncTextGenerateOptions) {
		o.fields = fields
	}
}

// GetAsyncTextStatus retrieves the full status of an asynchronous text generation request.
// GET /v2/generate/text/status/{id}
func (h *AIHorde) GetAsyncTextStatus(id string, options ...GetAsyncTextStatusOption) (*RequestStatusKobold, error) {
	opts := &getAsyncTextStatusOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/generate/text/status/%s", id)
	// No token needed for status endpoint
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status RequestStatusKobold
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode GetAsyncTextStatus response: %w", err)
	}
	return &status, nil
}

type GetAsyncTextStatusOption func(*getAsyncTextStatusOptions)
type getAsyncTextStatusOptions struct {
	fields []string
}

func WithGetAsyncTextStatusFields(fields []string) GetAsyncTextStatusOption {
	return func(o *getAsyncTextStatusOptions) {
		o.fields = fields
	}
}

// DeleteAsyncTextStatus cancels an unfinished text generation request.
// DELETE /v2/generate/text/status/{id}
func (h *AIHorde) DeleteAsyncTextStatus(id string, options ...DeleteAsyncTextStatusOption) (*RequestStatusKobold, error) {
	opts := &deleteAsyncTextStatusOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/generate/text/status/%s", id)
	// No token needed for delete endpoint? Spec doesn't list one.
	resp, err := h.request("DELETE", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Response is RequestStatusKobold according to spec
	var status RequestStatusKobold
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteAsyncTextStatus response: %w", err)
	}
	return &status, nil
}

type DeleteAsyncTextStatusOption func(*deleteAsyncTextStatusOptions)
type deleteAsyncTextStatusOptions struct {
	fields []string
}

func WithDeleteAsyncTextStatusFields(fields []string) DeleteAsyncTextStatusOption {
	return func(o *deleteAsyncTextStatusOptions) {
		o.fields = fields
	}
}

// --- Model Endpoints ---

// GetModels retrieves a list of active models on the horde.
// GET /v2/status/models
func (h *AIHorde) GetModels(options ...GetModelsOption) ([]ActiveModel, error) {
	opts := &getModelsOptions{
		modelType:  ModelTypeImage, // Default type
		modelState: ModelStateAll,  // Default state
	}
	for _, opt := range options {
		opt(opts)
	}

	requestOptions := []RequestOption{WithFields(opts.fields)}
	requestOptions = append(requestOptions, WithQueryParam("type", string(opts.modelType)))
	requestOptions = append(requestOptions, WithQueryParam("model_state", string(opts.modelState)))
	if opts.minCount != nil {
		requestOptions = append(requestOptions, WithQueryParam("min_count", strconv.Itoa(*opts.minCount)))
	}
	if opts.maxCount != nil {
		requestOptions = append(requestOptions, WithQueryParam("max_count", strconv.Itoa(*opts.maxCount)))
	}

	// No token needed
	resp, err := h.request("GET", "/v2/status/models", requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var models []ActiveModel
	if err := json.NewDecoder(resp.Body).Decode(&models); err != nil {
		return nil, fmt.Errorf("failed to decode GetModels response: %w", err)
	}
	return models, nil
}

type GetModelsOption func(*getModelsOptions)
type getModelsOptions struct {
	modelType  ModelType
	minCount   *int // Use pointer to distinguish between 0 and not set
	maxCount   *int // Use pointer to distinguish between 0 and not set
	modelState ModelStateType
	fields     []string
}

func WithModelsType(modelType ModelType) GetModelsOption {
	return func(o *getModelsOptions) {
		o.modelType = modelType
	}
}
func WithModelsMinCount(count int) GetModelsOption {
	return func(o *getModelsOptions) {
		o.minCount = &count
	}
}
func WithModelsMaxCount(count int) GetModelsOption {
	return func(o *getModelsOptions) {
		o.maxCount = &count
	}
}
func WithModelsState(state ModelStateType) GetModelsOption {
	return func(o *getModelsOptions) {
		o.modelState = state
	}
}
func WithModelsFields(fields []string) GetModelsOption {
	return func(o *getModelsOptions) {
		o.fields = fields
	}
}

// GetModelDetails retrieves statistics for a specific model.
// GET /v2/status/models/{model_name}
// Note: Spec indicates the response is an array of ActiveModel.
func (h *AIHorde) GetModelDetails(modelName string, options ...GetModelDetailsOption) ([]ActiveModel, error) {
	opts := &getModelDetailsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	// URL encode model name? Assuming it's safe for now. Consider url.PathEscape if needed.
	path := fmt.Sprintf("/v2/status/models/%s", modelName)
	// No token needed
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var models []ActiveModel // Response is an array according to spec path
	if err := json.NewDecoder(resp.Body).Decode(&models); err != nil {
		return nil, fmt.Errorf("failed to decode GetModelDetails response: %w", err)
	}
	return models, nil
}

type GetModelDetailsOption func(*getModelDetailsOptions)
type getModelDetailsOptions struct {
	fields []string
}

func WithGetModelDetailsFields(fields []string) GetModelDetailsOption {
	return func(o *getModelDetailsOptions) {
		o.fields = fields
	}
}

// --- Horde Status Endpoints ---

// GetHordeModes retrieves the current maintenance/invite/raid modes of the horde.
// GET /v2/status/modes
func (h *AIHorde) GetHordeModes(options ...GetHordeModesOption) (*HordeModes, error) {
	opts := &getHordeModesOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}

	// Token is optional (for admin/owner info?) - Spec unclear, assuming not needed for GET
	resp, err := h.request("GET", "/v2/status/modes", WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var modes HordeModes
	if err := json.NewDecoder(resp.Body).Decode(&modes); err != nil {
		return nil, fmt.Errorf("failed to decode GetHordeModes response: %w", err)
	}
	return &modes, nil
}

type GetHordeModesOption func(*getHordeModesOptions)
type getHordeModesOptions struct {
	token  string // Optional: Admin or Owner API key
	fields []string
}

func WithGetHordeModesToken(token string) GetHordeModesOption {
	return func(o *getHordeModesOptions) {
		o.token = token
	}
}
func WithGetHordeModesFields(fields []string) GetHordeModesOption {
	return func(o *getHordeModesOptions) {
		o.fields = fields
	}
}

// ModifyHordeModes changes the operational modes of the horde (Admin only).
// PUT /v2/status/modes
func (h *AIHorde) ModifyHordeModes(input HordeModeInput, options ...ModifyHordeModesOption) (*HordeModes, error) {
	opts := &modifyHordeModesOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Admin token is required
	if opts.token == "" {
		return nil, fmt.Errorf("admin API key is required for ModifyHordeModes")
	}

	resp, err := h.request("PUT", "/v2/status/modes", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var modes HordeModes
	if err := json.NewDecoder(resp.Body).Decode(&modes); err != nil {
		return nil, fmt.Errorf("failed to decode ModifyHordeModes response: %w", err)
	}
	return &modes, nil
}

type ModifyHordeModesOption func(*modifyHordeModesOptions)
type modifyHordeModesOptions struct {
	token  string // Required: Admin API key
	fields []string
}

func WithModifyHordeModesToken(token string) ModifyHordeModesOption {
	return func(o *modifyHordeModesOptions) {
		o.token = token
	}
}
func WithModifyHordeModesFields(fields []string) ModifyHordeModesOption {
	return func(o *modifyHordeModesOptions) {
		o.fields = fields
	}
}

// GetHordePerformance retrieves current performance statistics for the horde.
// GET /v2/status/performance
func (h *AIHorde) GetHordePerformance(options ...GetHordePerformanceOption) (*HordePerformance, error) {
	opts := &getHordePerformanceOptions{}
	for _, opt := range options {
		opt(opts)
	}

	// No token needed
	resp, err := h.request("GET", "/v2/status/performance", WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var performance HordePerformance
	if err := json.NewDecoder(resp.Body).Decode(&performance); err != nil {
		return nil, fmt.Errorf("failed to decode GetHordePerformance response: %w", err)
	}
	return &performance, nil
}

type GetHordePerformanceOption func(*getHordePerformanceOptions)
type getHordePerformanceOptions struct {
	fields []string
}

func WithGetHordePerformanceFields(fields []string) GetHordePerformanceOption {
	return func(o *getHordePerformanceOptions) {
		o.fields = fields
	}
}

// GetHordeNews retrieves the latest news from the horde.
// GET /v2/status/news
func (h *AIHorde) GetHordeNews(options ...GetHordeNewsOption) ([]Newspiece, error) {
	opts := &getHordeNewsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	// No token needed
	resp, err := h.request("GET", "/v2/status/news", WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var news []Newspiece
	if err := json.NewDecoder(resp.Body).Decode(&news); err != nil {
		return nil, fmt.Errorf("failed to decode GetHordeNews response: %w", err)
	}
	return news, nil
}

type GetHordeNewsOption func(*getHordeNewsOptions)
type getHordeNewsOptions struct {
	fields []string
}

func WithGetHordeNewsFields(fields []string) GetHordeNewsOption {
	return func(o *getHordeNewsOptions) {
		o.fields = fields
	}
}

// --- Collection Endpoints ---

// GetCollections retrieves a list of style collections.
// GET /v2/collections
func (h *AIHorde) GetCollections(options ...GetCollectionsOption) ([]ResponseModelCollection, error) {
	opts := &getCollectionsOptions{
		page: 1,
		sort: SortPopular, // Default sort
		typ:  "all",       // Default type
	}
	for _, opt := range options {
		opt(opts)
	}

	requestOptions := []RequestOption{WithFields(opts.fields)}
	requestOptions = append(requestOptions, WithQueryParam("page", strconv.Itoa(opts.page)))
	requestOptions = append(requestOptions, WithQueryParam("sort", string(opts.sort)))
	requestOptions = append(requestOptions, WithQueryParam("type", opts.typ))

	// No token needed
	resp, err := h.request("GET", "/v2/collections", requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var collections []ResponseModelCollection
	if err := json.NewDecoder(resp.Body).Decode(&collections); err != nil {
		return nil, fmt.Errorf("failed to decode GetCollections response: %w", err)
	}
	return collections, nil
}

type GetCollectionsOption func(*getCollectionsOptions)
type getCollectionsOptions struct {
	page   int
	sort   SortType
	typ    string // "image", "text", or "all"
	fields []string
}

func WithCollectionsPage(page int) GetCollectionsOption {
	return func(o *getCollectionsOptions) {
		if page > 0 {
			o.page = page
		}
	}
}
func WithCollectionsSort(sort SortType) GetCollectionsOption {
	return func(o *getCollectionsOptions) {
		o.sort = sort
	}
}
func WithCollectionsType(typ string) GetCollectionsOption {
	return func(o *getCollectionsOptions) {
		// Basic validation
		if typ == "image" || typ == "text" || typ == "all" {
			o.typ = typ
		}
	}
}
func WithCollectionsFields(fields []string) GetCollectionsOption {
	return func(o *getCollectionsOptions) {
		o.fields = fields
	}
}

// CreateCollection creates a new style collection.
// POST /v2/collections
func (h *AIHorde) CreateCollection(input InputModelCollection, options ...CreateCollectionOption) (*StyleModify, error) {
	opts := &createCollectionOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for CreateCollection")
	}

	resp, err := h.request("POST", "/v2/collections", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result StyleModify
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CreateCollection response: %w", err)
	}
	return &result, nil
}

type CreateCollectionOption func(*createCollectionOptions)
type createCollectionOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithCreateCollectionToken(token string) CreateCollectionOption {
	return func(o *createCollectionOptions) {
		o.token = token
	}
}
func WithCreateCollectionFields(fields []string) CreateCollectionOption {
	return func(o *createCollectionOptions) {
		o.fields = fields
	}
}

// GetCollectionDetails retrieves information about a single style collection by ID.
// GET /v2/collections/{collection_id}
func (h *AIHorde) GetCollectionDetails(collectionID string, options ...GetCollectionDetailsOption) (*ResponseModelCollection, error) {
	opts := &getCollectionDetailsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/collections/%s", collectionID)
	// No token needed
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var collection ResponseModelCollection
	if err := json.NewDecoder(resp.Body).Decode(&collection); err != nil {
		return nil, fmt.Errorf("failed to decode GetCollectionDetails response: %w", err)
	}
	return &collection, nil
}

type GetCollectionDetailsOption func(*getCollectionDetailsOptions)
type getCollectionDetailsOptions struct {
	fields []string
}

func WithGetCollectionDetailsFields(fields []string) GetCollectionDetailsOption {
	return func(o *getCollectionDetailsOptions) {
		o.fields = fields
	}
}

// DeleteCollection deletes a style collection (Mod only).
// DELETE /v2/collections/{collection_id}
func (h *AIHorde) DeleteCollection(collectionID string, options ...DeleteCollectionOption) (*SimpleResponse, error) {
	opts := &deleteCollectionOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for DeleteCollection")
	}

	path := fmt.Sprintf("/v2/collections/%s", collectionID)
	resp, err := h.request("DELETE", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteCollection response: %w", err)
	}
	return &result, nil
}

type DeleteCollectionOption func(*deleteCollectionOptions)
type deleteCollectionOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithDeleteCollectionToken(token string) DeleteCollectionOption {
	return func(o *deleteCollectionOptions) {
		o.token = token
	}
}
func WithDeleteCollectionFields(fields []string) DeleteCollectionOption {
	return func(o *deleteCollectionOptions) {
		o.fields = fields
	}
}

// ModifyCollection modifies an existing style collection.
// PATCH /v2/collections/{collection_id}
func (h *AIHorde) ModifyCollection(collectionID string, input InputModelCollection, options ...ModifyCollectionOption) (*StyleModify, error) {
	opts := &modifyCollectionOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for ModifyCollection")
	}

	// Note: Spec uses InputModelCollection for PATCH, which requires all fields.
	// A true PATCH might use a different input struct with optional fields.
	// Using InputModelCollection as specified.
	path := fmt.Sprintf("/v2/collections/%s", collectionID)
	resp, err := h.request("PATCH", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result StyleModify
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ModifyCollection response: %w", err)
	}
	return &result, nil
}

type ModifyCollectionOption func(*modifyCollectionOptions)
type modifyCollectionOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithModifyCollectionToken(token string) ModifyCollectionOption {
	return func(o *modifyCollectionOptions) {
		o.token = token
	}
}
func WithModifyCollectionFields(fields []string) ModifyCollectionOption {
	return func(o *modifyCollectionOptions) {
		o.fields = fields
	}
}

// GetCollectionByName retrieves information about a single style collection by name.
// GET /v2/collection_by_name/{collection_name}
func (h *AIHorde) GetCollectionByName(collectionName string, options ...GetCollectionByNameOption) (*ResponseModelCollection, error) {
	opts := &getCollectionByNameOptions{}
	for _, opt := range options {
		opt(opts)
	}

	// URL encode collection name? Assuming it's safe for now. Consider url.PathEscape if needed.
	path := fmt.Sprintf("/v2/collection_by_name/%s", collectionName)
	// No token needed
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var collection ResponseModelCollection
	if err := json.NewDecoder(resp.Body).Decode(&collection); err != nil {
		return nil, fmt.Errorf("failed to decode GetCollectionByName response: %w", err)
	}
	return &collection, nil
}

type GetCollectionByNameOption func(*getCollectionByNameOptions)
type getCollectionByNameOptions struct {
	fields []string
}

func WithGetCollectionByNameFields(fields []string) GetCollectionByNameOption {
	return func(o *getCollectionByNameOptions) {
		o.fields = fields
	}
}

// --- Document Endpoints ---

// getDocument retrieves a specific document (privacy, terms, sponsors).
func (h *AIHorde) getDocument(docPath string, options ...GetDocumentOption) (*HordeDocument, error) {
	opts := &getDocumentOptions{
		format: FormatHTML, // Default format
	}
	for _, opt := range options {
		opt(opts)
	}

	requestOptions := []RequestOption{WithFields(opts.fields)}
	requestOptions = append(requestOptions, WithQueryParam("format", string(opts.format)))

	// No token needed
	resp, err := h.request("GET", docPath, requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var doc HordeDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode document response for %s: %w", docPath, err)
	}
	return &doc, nil
}

type GetDocumentOption func(*getDocumentOptions)
type getDocumentOptions struct {
	format DocumentFormat
	fields []string
}

// WithDocumentFormat sets the desired format (html or markdown).
func WithDocumentFormat(format DocumentFormat) GetDocumentOption {
	return func(o *getDocumentOptions) {
		o.format = format
	}
}

// WithDocumentFields sets the X-Fields header.
func WithDocumentFields(fields []string) GetDocumentOption {
	return func(o *getDocumentOptions) {
		o.fields = fields
	}
}

// GetPrivacyPolicy retrieves the AI Horde Privacy Policy.
// GET /v2/documents/privacy
func (h *AIHorde) GetPrivacyPolicy(options ...GetDocumentOption) (*HordeDocument, error) {
	return h.getDocument("/v2/documents/privacy", options...)
}

// GetSponsors retrieves the AI Horde Sponsors document.
// GET /v2/documents/sponsors
func (h *AIHorde) GetSponsors(options ...GetDocumentOption) (*HordeDocument, error) {
	return h.getDocument("/v2/documents/sponsors", options...)
}

// GetTerms retrieves the AI Horde Terms and Conditions.
// GET /v2/documents/terms
func (h *AIHorde) GetTerms(options ...GetDocumentOption) (*HordeDocument, error) {
	return h.getDocument("/v2/documents/terms", options...)
}

// --- Filter Endpoints (Moderator Only) ---

// GetFilters retrieves a list of regex filters.
// GET /v2/filters
func (h *AIHorde) GetFilters(options ...GetFiltersOption) ([]FilterDetails, error) {
	opts := &getFiltersOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for GetFilters")
	}

	requestOptions := []RequestOption{WithToken(opts.token), WithFields(opts.fields)}
	if opts.filterType != nil {
		requestOptions = append(requestOptions, WithQueryParam("filter_type", strconv.Itoa(*opts.filterType)))
	}
	if opts.contains != "" {
		requestOptions = append(requestOptions, WithQueryParam("contains", opts.contains))
	}

	resp, err := h.request("GET", "/v2/filters", requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var filters []FilterDetails
	if err := json.NewDecoder(resp.Body).Decode(&filters); err != nil {
		return nil, fmt.Errorf("failed to decode GetFilters response: %w", err)
	}
	return filters, nil
}

type GetFiltersOption func(*getFiltersOptions)
type getFiltersOptions struct {
	token      string // Required: Mod API key
	filterType *int   // Optional filter
	contains   string // Optional filter
	fields     []string
}

func WithGetFiltersToken(token string) GetFiltersOption {
	return func(o *getFiltersOptions) {
		o.token = token
	}
}
func WithGetFiltersType(filterType int) GetFiltersOption {
	return func(o *getFiltersOptions) {
		o.filterType = &filterType
	}
}
func WithGetFiltersContains(contains string) GetFiltersOption {
	return func(o *getFiltersOptions) {
		o.contains = contains
	}
}
func WithGetFiltersFields(fields []string) GetFiltersOption {
	return func(o *getFiltersOptions) {
		o.fields = fields
	}
}

// CheckPromptSuspicion checks the suspicion level of a given prompt.
// POST /v2/filters
func (h *AIHorde) CheckPromptSuspicion(input FilterCheckInput, options ...CheckPromptSuspicionOption) (*FilterPromptSuspicion, error) {
	opts := &checkPromptSuspicionOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for CheckPromptSuspicion")
	}

	resp, err := h.request("POST", "/v2/filters", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result FilterPromptSuspicion
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CheckPromptSuspicion response: %w", err)
	}
	return &result, nil
}

type CheckPromptSuspicionOption func(*checkPromptSuspicionOptions)
type checkPromptSuspicionOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithCheckPromptSuspicionToken(token string) CheckPromptSuspicionOption {
	return func(o *checkPromptSuspicionOptions) {
		o.token = token
	}
}
func WithCheckPromptSuspicionFields(fields []string) CheckPromptSuspicionOption {
	return func(o *checkPromptSuspicionOptions) {
		o.fields = fields
	}
}

// CreateFilter adds a new regex filter.
// PUT /v2/filters
func (h *AIHorde) CreateFilter(input PutNewFilter, options ...CreateFilterOption) (*FilterDetails, error) {
	opts := &createFilterOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for CreateFilter")
	}

	resp, err := h.request("PUT", "/v2/filters", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result FilterDetails
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CreateFilter response: %w", err)
	}
	return &result, nil
}

type CreateFilterOption func(*createFilterOptions)
type createFilterOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithCreateFilterToken(token string) CreateFilterOption {
	return func(o *createFilterOptions) {
		o.token = token
	}
}
func WithCreateFilterFields(fields []string) CreateFilterOption {
	return func(o *createFilterOptions) {
		o.fields = fields
	}
}

// GetFilterRegex retrieves the combined regex for filter types.
// GET /v2/filters/regex
func (h *AIHorde) GetFilterRegex(options ...GetFilterRegexOption) ([]FilterRegex, error) {
	opts := &getFilterRegexOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for GetFilterRegex")
	}

	requestOptions := []RequestOption{WithToken(opts.token), WithFields(opts.fields)}
	if opts.filterType != nil {
		requestOptions = append(requestOptions, WithQueryParam("filter_type", strconv.Itoa(*opts.filterType)))
	}

	resp, err := h.request("GET", "/v2/filters/regex", requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var filters []FilterRegex
	if err := json.NewDecoder(resp.Body).Decode(&filters); err != nil {
		return nil, fmt.Errorf("failed to decode GetFilterRegex response: %w", err)
	}
	return filters, nil
}

type GetFilterRegexOption func(*getFilterRegexOptions)
type getFilterRegexOptions struct {
	token      string // Required: Mod API key
	filterType *int   // Optional filter
	fields     []string
}

func WithGetFilterRegexToken(token string) GetFilterRegexOption {
	return func(o *getFilterRegexOptions) {
		o.token = token
	}
}
func WithGetFilterRegexType(filterType int) GetFilterRegexOption {
	return func(o *getFilterRegexOptions) {
		o.filterType = &filterType
	}
}
func WithGetFilterRegexFields(fields []string) GetFilterRegexOption {
	return func(o *getFilterRegexOptions) {
		o.fields = fields
	}
}

// GetFilterDetails retrieves details for filters matching the ID.
// GET /v2/filters/{filter_id}
// Note: Spec indicates the response is an array of FilterDetails.
func (h *AIHorde) GetFilterDetails(filterID string, options ...GetFilterDetailsOption) ([]FilterDetails, error) {
	opts := &getFilterDetailsOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for GetFilterDetails")
	}

	path := fmt.Sprintf("/v2/filters/%s", filterID)
	resp, err := h.request("GET", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var filters []FilterDetails // Response is an array according to spec path
	if err := json.NewDecoder(resp.Body).Decode(&filters); err != nil {
		return nil, fmt.Errorf("failed to decode GetFilterDetails response: %w", err)
	}
	return filters, nil
}

type GetFilterDetailsOption func(*getFilterDetailsOptions)
type getFilterDetailsOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithGetFilterDetailsToken(token string) GetFilterDetailsOption {
	return func(o *getFilterDetailsOptions) {
		o.token = token
	}
}
func WithGetFilterDetailsFields(fields []string) GetFilterDetailsOption {
	return func(o *getFilterDetailsOptions) {
		o.fields = fields
	}
}

// DeleteFilter deletes a specific regex filter.
// DELETE /v2/filters/{filter_id}
func (h *AIHorde) DeleteFilter(filterID string, options ...DeleteFilterOption) (*SimpleResponse, error) {
	opts := &deleteFilterOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for DeleteFilter")
	}

	path := fmt.Sprintf("/v2/filters/%s", filterID)
	resp, err := h.request("DELETE", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteFilter response: %w", err)
	}
	return &result, nil
}

type DeleteFilterOption func(*deleteFilterOptions)
type deleteFilterOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithDeleteFilterToken(token string) DeleteFilterOption {
	return func(o *deleteFilterOptions) {
		o.token = token
	}
}
func WithDeleteFilterFields(fields []string) DeleteFilterOption {
	return func(o *deleteFilterOptions) {
		o.fields = fields
	}
}

// ModifyFilter modifies an existing regex filter.
// PATCH /v2/filters/{filter_id}
func (h *AIHorde) ModifyFilter(filterID string, input PatchExistingFilter, options ...ModifyFilterOption) (*FilterDetails, error) {
	opts := &modifyFilterOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for ModifyFilter")
	}

	path := fmt.Sprintf("/v2/filters/%s", filterID)
	resp, err := h.request("PATCH", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result FilterDetails
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ModifyFilter response: %w", err)
	}
	return &result, nil
}

type ModifyFilterOption func(*modifyFilterOptions)
type modifyFilterOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithModifyFilterToken(token string) ModifyFilterOption {
	return func(o *modifyFilterOptions) {
		o.token = token
	}
}
func WithModifyFilterFields(fields []string) ModifyFilterOption {
	return func(o *modifyFilterOptions) {
		o.fields = fields
	}
}

// --- Worker Pop/Submit Endpoints ---

// PopImageJob checks for and retrieves an image generation job. (Worker Only)
// POST /v2/generate/pop
func (h *AIHorde) PopImageJob(input PopInputStable, options ...PopImageJobOption) (*GenerationPayloadStable, error) {
	opts := &popImageJobOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Worker token is required
	if opts.token == "" {
		return nil, fmt.Errorf("worker API key is required for PopImageJob")
	}

	resp, err := h.request("POST", "/v2/generate/pop", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result GenerationPayloadStable
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode PopImageJob response: %w", err)
	}
	return &result, nil
}

type PopImageJobOption func(*popImageJobOptions)
type popImageJobOptions struct {
	token  string // Required: Worker API key
	fields []string
}

func WithPopImageJobToken(token string) PopImageJobOption {
	return func(o *popImageJobOptions) {
		o.token = token
	}
}
func WithPopImageJobFields(fields []string) PopImageJobOption {
	return func(o *popImageJobOptions) {
		o.fields = fields
	}
}

// SubmitImageJob submits a completed image generation job. (Worker Only)
// POST /v2/generate/submit
func (h *AIHorde) SubmitImageJob(input SubmitInputStable, options ...SubmitImageJobOption) (*GenerationSubmitted, error) {
	opts := &submitImageJobOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Worker token is required
	if opts.token == "" {
		return nil, fmt.Errorf("worker API key is required for SubmitImageJob")
	}

	resp, err := h.request("POST", "/v2/generate/submit", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result GenerationSubmitted
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode SubmitImageJob response: %w", err)
	}
	return &result, nil
}

type SubmitImageJobOption func(*submitImageJobOptions)
type submitImageJobOptions struct {
	token  string // Required: Worker API key
	fields []string
}

func WithSubmitImageJobToken(token string) SubmitImageJobOption {
	return func(o *submitImageJobOptions) {
		o.token = token
	}
}
func WithSubmitImageJobFields(fields []string) SubmitImageJobOption {
	return func(o *submitImageJobOptions) {
		o.fields = fields
	}
}

// PopTextJob checks for and retrieves a text generation job. (Worker Only)
// POST /v2/generate/text/pop
func (h *AIHorde) PopTextJob(input PopInputKobold, options ...PopTextJobOption) (*GenerationPayloadKobold, error) {
	opts := &popTextJobOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Worker token is required
	if opts.token == "" {
		return nil, fmt.Errorf("worker API key is required for PopTextJob")
	}

	resp, err := h.request("POST", "/v2/generate/text/pop", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result GenerationPayloadKobold
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode PopTextJob response: %w", err)
	}
	return &result, nil
}

type PopTextJobOption func(*popTextJobOptions)
type popTextJobOptions struct {
	token  string // Required: Worker API key
	fields []string
}

func WithPopTextJobToken(token string) PopTextJobOption {
	return func(o *popTextJobOptions) {
		o.token = token
	}
}
func WithPopTextJobFields(fields []string) PopTextJobOption {
	return func(o *popTextJobOptions) {
		o.fields = fields
	}
}

// SubmitTextJob submits a completed text generation job. (Worker Only)
// POST /v2/generate/text/submit
func (h *AIHorde) SubmitTextJob(input SubmitInputKobold, options ...SubmitTextJobOption) (*GenerationSubmitted, error) {
	opts := &submitTextJobOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Worker token is required
	if opts.token == "" {
		return nil, fmt.Errorf("worker API key is required for SubmitTextJob")
	}

	resp, err := h.request("POST", "/v2/generate/text/submit", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result GenerationSubmitted
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode SubmitTextJob response: %w", err)
	}
	return &result, nil
}

type SubmitTextJobOption func(*submitTextJobOptions)
type submitTextJobOptions struct {
	token  string // Required: Worker API key
	fields []string
}

func WithSubmitTextJobToken(token string) SubmitTextJobOption {
	return func(o *submitTextJobOptions) {
		o.token = token
	}
}
func WithSubmitTextJobFields(fields []string) SubmitTextJobOption {
	return func(o *submitTextJobOptions) {
		o.fields = fields
	}
}

// --- Aesthetics Rating Endpoint ---

// RateGeneration submits aesthetic ratings for a generated image batch.
// POST /v2/generate/rate/{id}
func (h *AIHorde) RateGeneration(id string, input AestheticsPayload, options ...RateGenerationOption) (*GenerationSubmitted, error) {
	opts := &rateGenerationOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/generate/rate/%s", id)
	// No token needed for rating? Spec doesn't list one. Assumes public rating.
	resp, err := h.request("POST", path, WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result GenerationSubmitted
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode RateGeneration response: %w", err)
	}
	return &result, nil
}

type RateGenerationOption func(*rateGenerationOptions)
type rateGenerationOptions struct {
	// token string // Optional? Spec doesn't list one.
	fields []string
}

//	func WithRateGenerationToken(token string) RateGenerationOption {
//		return func(o *rateGenerationOptions) {
//			o.token = token
//		}
//	}
func WithRateGenerationFields(fields []string) RateGenerationOption {
	return func(o *rateGenerationOptions) {
		o.fields = fields
	}
}

// --- Interrogation Endpoints ---

// PostAsyncInterrogate initiates an asynchronous request to interrogate an image.
// POST /v2/interrogate/async
func (h *AIHorde) PostAsyncInterrogate(input ModelInterrogationInputStable, options ...PostAsyncInterrogateOption) (*RequestInterrogationResponse, error) {
	opts := &postAsyncInterrogateOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for PostAsyncInterrogate")
	}

	resp, err := h.request("POST", "/v2/interrogate/async", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result RequestInterrogationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode PostAsyncInterrogate response: %w", err)
	}
	return &result, nil
}

type PostAsyncInterrogateOption func(*postAsyncInterrogateOptions)
type postAsyncInterrogateOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithPostAsyncInterrogateToken(token string) PostAsyncInterrogateOption {
	return func(o *postAsyncInterrogateOptions) {
		o.token = token
	}
}
func WithPostAsyncInterrogateFields(fields []string) PostAsyncInterrogateOption {
	return func(o *postAsyncInterrogateOptions) {
		o.fields = fields
	}
}

// PopInterrogationJob checks for and retrieves an image interrogation job. (Worker Only)
// POST /v2/interrogate/pop
func (h *AIHorde) PopInterrogationJob(input InterrogationPopInput, options ...PopInterrogationJobOption) (*InterrogationPopPayload, error) {
	opts := &popInterrogationJobOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Worker token is required
	if opts.token == "" {
		return nil, fmt.Errorf("worker API key is required for PopInterrogationJob")
	}

	resp, err := h.request("POST", "/v2/interrogate/pop", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result InterrogationPopPayload
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode PopInterrogationJob response: %w", err)
	}
	return &result, nil
}

type PopInterrogationJobOption func(*popInterrogationJobOptions)
type popInterrogationJobOptions struct {
	token  string // Required: Worker API key
	fields []string
}

func WithPopInterrogationJobToken(token string) PopInterrogationJobOption {
	return func(o *popInterrogationJobOptions) {
		o.token = token
	}
}
func WithPopInterrogationJobFields(fields []string) PopInterrogationJobOption {
	return func(o *popInterrogationJobOptions) {
		o.fields = fields
	}
}

// GetInterrogationStatus retrieves the status of an interrogation request.
// GET /v2/interrogate/status/{id}
func (h *AIHorde) GetInterrogationStatus(id string, options ...GetInterrogationStatusOption) (*InterrogationStatus, error) {
	opts := &getInterrogationStatusOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/interrogate/status/%s", id)
	// No token needed
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status InterrogationStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode GetInterrogationStatus response: %w", err)
	}
	return &status, nil
}

type GetInterrogationStatusOption func(*getInterrogationStatusOptions)
type getInterrogationStatusOptions struct {
	fields []string
}

func WithGetInterrogationStatusFields(fields []string) GetInterrogationStatusOption {
	return func(o *getInterrogationStatusOptions) {
		o.fields = fields
	}
}

// DeleteInterrogationStatus cancels an unfinished interrogation request.
// DELETE /v2/interrogate/status/{id}
func (h *AIHorde) DeleteInterrogationStatus(id string, options ...DeleteInterrogationStatusOption) (*InterrogationStatus, error) {
	opts := &deleteInterrogationStatusOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/interrogate/status/%s", id)
	// No token needed
	resp, err := h.request("DELETE", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status InterrogationStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteInterrogationStatus response: %w", err)
	}
	return &status, nil
}

type DeleteInterrogationStatusOption func(*deleteInterrogationStatusOptions)
type deleteInterrogationStatusOptions struct {
	fields []string
}

func WithDeleteInterrogationStatusFields(fields []string) DeleteInterrogationStatusOption {
	return func(o *deleteInterrogationStatusOptions) {
		o.fields = fields
	}
}

// SubmitInterrogationResult submits the result of an interrogation job. (Worker Only)
// POST /v2/interrogate/submit
func (h *AIHorde) SubmitInterrogationResult(input InterrogationSubmitInput, options ...SubmitInterrogationResultOption) (*GenerationSubmitted, error) {
	opts := &submitInterrogationResultOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Worker token is required
	if opts.token == "" {
		return nil, fmt.Errorf("worker API key is required for SubmitInterrogationResult")
	}

	resp, err := h.request("POST", "/v2/interrogate/submit", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result GenerationSubmitted
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode SubmitInterrogationResult response: %w", err)
	}
	return &result, nil
}

type SubmitInterrogationResultOption func(*submitInterrogationResultOptions)
type submitInterrogationResultOptions struct {
	token  string // Required: Worker API key
	fields []string
}

func WithSubmitInterrogationResultToken(token string) SubmitInterrogationResultOption {
	return func(o *submitInterrogationResultOptions) {
		o.token = token
	}
}
func WithSubmitInterrogationResultFields(fields []string) SubmitInterrogationResultOption {
	return func(o *submitInterrogationResultOptions) {
		o.fields = fields
	}
}

// --- Kudos Endpoints ---

// TransferKudos transfers kudos to another registered user.
// POST /v2/kudos/transfer
func (h *AIHorde) TransferKudos(input KudosTransferInput, options ...TransferKudosOption) (*KudosTransferred, error) {
	opts := &transferKudosOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Sender token is required
	if opts.token == "" {
		return nil, fmt.Errorf("sender API key is required for TransferKudos")
	}

	resp, err := h.request("POST", "/v2/kudos/transfer", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result KudosTransferred
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode TransferKudos response: %w", err)
	}
	return &result, nil
}

type TransferKudosOption func(*transferKudosOptions)
type transferKudosOptions struct {
	token  string // Required: Sender User API key
	fields []string
}

func WithTransferKudosToken(token string) TransferKudosOption {
	return func(o *transferKudosOptions) {
		o.token = token
	}
}
func WithTransferKudosFields(fields []string) TransferKudosOption {
	return func(o *transferKudosOptions) {
		o.fields = fields
	}
}

// AwardKudos awards kudos to a registered user (Privileged only).
// POST /v2/kudos/award
func (h *AIHorde) AwardKudos(input KudosAwardInput, options ...AwardKudosOption) (*KudosAwarded, error) {
	opts := &awardKudosOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Privileged token is required
	if opts.token == "" {
		return nil, fmt.Errorf("privileged API key is required for AwardKudos")
	}

	resp, err := h.request("POST", "/v2/kudos/award", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result KudosAwarded
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode AwardKudos response: %w", err)
	}
	return &result, nil
}

type AwardKudosOption func(*awardKudosOptions)
type awardKudosOptions struct {
	token  string // Required: Privileged API key
	fields []string
}

func WithAwardKudosToken(token string) AwardKudosOption {
	return func(o *awardKudosOptions) {
		o.token = token
	}
}
func WithAwardKudosFields(fields []string) AwardKudosOption {
	return func(o *awardKudosOptions) {
		o.fields = fields
	}
}

// --- Operations Endpoints (Moderator Only) ---

// GetIPTimeouts retrieves all current IP timeouts.
// GET /v2/operations/ipaddr
func (h *AIHorde) GetIPTimeouts(options ...GetIPTimeoutsOption) ([]IPTimeout, error) {
	opts := &getIPTimeoutsOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for GetIPTimeouts")
	}

	resp, err := h.request("GET", "/v2/operations/ipaddr", WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var timeouts []IPTimeout
	if err := json.NewDecoder(resp.Body).Decode(&timeouts); err != nil {
		return nil, fmt.Errorf("failed to decode GetIPTimeouts response: %w", err)
	}
	return timeouts, nil
}

type GetIPTimeoutsOption func(*getIPTimeoutsOptions)
type getIPTimeoutsOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithGetIPTimeoutsToken(token string) GetIPTimeoutsOption {
	return func(o *getIPTimeoutsOptions) {
		o.token = token
	}
}
func WithGetIPTimeoutsFields(fields []string) GetIPTimeoutsOption {
	return func(o *getIPTimeoutsOptions) {
		o.fields = fields
	}
}

// AddIPTimeout adds an IP or CIDR to the timeout list.
// POST /v2/operations/ipaddr
func (h *AIHorde) AddIPTimeout(input AddTimeoutIPInput, options ...AddIPTimeoutOption) (*SimpleResponse, error) {
	opts := &addIPTimeoutOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for AddIPTimeout")
	}

	resp, err := h.request("POST", "/v2/operations/ipaddr", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode AddIPTimeout response: %w", err)
	}
	return &result, nil
}

type AddIPTimeoutOption func(*addIPTimeoutOptions)
type addIPTimeoutOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithAddIPTimeoutToken(token string) AddIPTimeoutOption {
	return func(o *addIPTimeoutOptions) {
		o.token = token
	}
}
func WithAddIPTimeoutFields(fields []string) AddIPTimeoutOption {
	return func(o *addIPTimeoutOptions) {
		o.fields = fields
	}
}

// DeleteIPTimeout removes an IP or CIDR from the timeout list.
// DELETE /v2/operations/ipaddr
func (h *AIHorde) DeleteIPTimeout(input DeleteTimeoutIPInput, options ...DeleteIPTimeoutOption) (*SimpleResponse, error) {
	opts := &deleteIPTimeoutOptions{}
	opts.token = h.defaultToken
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for DeleteIPTimeout")
	}

	resp, err := h.request("DELETE", "/v2/operations/ipaddr", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteIPTimeout response: %w", err)
	}
	return &result, nil
}

type DeleteIPTimeoutOption func(*deleteIPTimeoutOptions)
type deleteIPTimeoutOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithDeleteIPTimeoutToken(token string) DeleteIPTimeoutOption {
	return func(o *deleteIPTimeoutOptions) {
		o.token = token
	}
}
func WithDeleteIPTimeoutFields(fields []string) DeleteIPTimeoutOption {
	return func(o *deleteIPTimeoutOptions) {
		o.fields = fields
	}
}

// GetSingleIPTimeout checks if a specific IP or CIDR is in timeout.
// GET /v2/operations/ipaddr/{ipaddr}
func (h *AIHorde) GetSingleIPTimeout(ipaddr string, options ...GetSingleIPTimeoutOption) ([]IPTimeout, error) {
	opts := &getSingleIPTimeoutOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for GetSingleIPTimeout")
	}

	path := fmt.Sprintf("/v2/operations/ipaddr/%s", ipaddr)
	resp, err := h.request("GET", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var timeouts []IPTimeout
	if err := json.NewDecoder(resp.Body).Decode(&timeouts); err != nil {
		return nil, fmt.Errorf("failed to decode GetSingleIPTimeout response: %w", err)
	}
	return timeouts, nil
}

type GetSingleIPTimeoutOption func(*getSingleIPTimeoutOptions)
type getSingleIPTimeoutOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithGetSingleIPTimeoutToken(token string) GetSingleIPTimeoutOption {
	return func(o *getSingleIPTimeoutOptions) {
		o.token = token
	}
}
func WithGetSingleIPTimeoutFields(fields []string) GetSingleIPTimeoutOption {
	return func(o *getSingleIPTimeoutOptions) {
		o.fields = fields
	}
}

// BlockWorkerIP blocks workers from a specific worker's IP address.
// PUT /v2/operations/block_worker_ipaddr/{worker_id}
func (h *AIHorde) BlockWorkerIP(workerID string, input AddWorkerTimeout, options ...BlockWorkerIPOption) (*SimpleResponse, error) {
	opts := &blockWorkerIPOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for BlockWorkerIP")
	}

	path := fmt.Sprintf("/v2/operations/block_worker_ipaddr/%s", workerID)
	resp, err := h.request("PUT", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode BlockWorkerIP response: %w", err)
	}
	return &result, nil
}

type BlockWorkerIPOption func(*blockWorkerIPOptions)
type blockWorkerIPOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithBlockWorkerIPToken(token string) BlockWorkerIPOption {
	return func(o *blockWorkerIPOptions) {
		o.token = token
	}
}
func WithBlockWorkerIPFields(fields []string) BlockWorkerIPOption {
	return func(o *blockWorkerIPOptions) {
		o.fields = fields
	}
}

// UnblockWorkerIP removes an IP block associated with a worker.
// DELETE /v2/operations/block_worker_ipaddr/{worker_id}
func (h *AIHorde) UnblockWorkerIP(workerID string, options ...UnblockWorkerIPOption) (*SimpleResponse, error) {
	opts := &unblockWorkerIPOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for UnblockWorkerIP")
	}

	path := fmt.Sprintf("/v2/operations/block_worker_ipaddr/%s", workerID)
	resp, err := h.request("DELETE", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode UnblockWorkerIP response: %w", err)
	}
	return &result, nil
}

type UnblockWorkerIPOption func(*unblockWorkerIPOptions)
type unblockWorkerIPOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithUnblockWorkerIPToken(token string) UnblockWorkerIPOption {
	return func(o *unblockWorkerIPOptions) {
		o.token = token
	}
}
func WithUnblockWorkerIPFields(fields []string) UnblockWorkerIPOption {
	return func(o *unblockWorkerIPOptions) {
		o.fields = fields
	}
}

// --- Shared Key Endpoints ---

// CreateSharedKey creates a new shared key for the user.
// PUT /v2/sharedkeys
func (h *AIHorde) CreateSharedKey(input SharedKeyInput, options ...CreateSharedKeyOption) (*SharedKeyDetails, error) {
	opts := &createSharedKeyOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("user API key is required for CreateSharedKey")
	}

	resp, err := h.request("PUT", "/v2/sharedkeys", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SharedKeyDetails
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CreateSharedKey response: %w", err)
	}
	return &result, nil
}

type CreateSharedKeyOption func(*createSharedKeyOptions)
type createSharedKeyOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithCreateSharedKeyToken(token string) CreateSharedKeyOption {
	return func(o *createSharedKeyOptions) {
		o.token = token
	}
}
func WithCreateSharedKeyFields(fields []string) CreateSharedKeyOption {
	return func(o *createSharedKeyOptions) {
		o.fields = fields
	}
}

// GetSharedKeyDetails retrieves details about a specific shared key.
// GET /v2/sharedkeys/{sharedkey_id}
func (h *AIHorde) GetSharedKeyDetails(sharedKeyID string, options ...GetSharedKeyDetailsOption) (*SharedKeyDetails, error) {
	opts := &getSharedKeyDetailsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/sharedkeys/%s", sharedKeyID)
	// No token needed for public details
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SharedKeyDetails
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode GetSharedKeyDetails response: %w", err)
	}
	return &result, nil
}

type GetSharedKeyDetailsOption func(*getSharedKeyDetailsOptions)
type getSharedKeyDetailsOptions struct {
	fields []string
}

func WithGetSharedKeyDetailsFields(fields []string) GetSharedKeyDetailsOption {
	return func(o *getSharedKeyDetailsOptions) {
		o.fields = fields
	}
}

// ModifySharedKey modifies an existing shared key.
// PATCH /v2/sharedkeys/{sharedkey_id}
func (h *AIHorde) ModifySharedKey(sharedKeyID string, input SharedKeyInput, options ...ModifySharedKeyOption) (*SharedKeyDetails, error) {
	opts := &modifySharedKeyOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("user API key is required for ModifySharedKey")
	}

	path := fmt.Sprintf("/v2/sharedkeys/%s", sharedKeyID)
	resp, err := h.request("PATCH", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SharedKeyDetails
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ModifySharedKey response: %w", err)
	}
	return &result, nil
}

type ModifySharedKeyOption func(*modifySharedKeyOptions)
type modifySharedKeyOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithModifySharedKeyToken(token string) ModifySharedKeyOption {
	return func(o *modifySharedKeyOptions) {
		o.token = token
	}
}
func WithModifySharedKeyFields(fields []string) ModifySharedKeyOption {
	return func(o *modifySharedKeyOptions) {
		o.fields = fields
	}
}

// DeleteSharedKey deletes an existing shared key.
// DELETE /v2/sharedkeys/{sharedkey_id}
func (h *AIHorde) DeleteSharedKey(sharedKeyID string, options ...DeleteSharedKeyOption) (*SimpleResponse, error) {
	opts := &deleteSharedKeyOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("user API key is required for DeleteSharedKey")
	}

	path := fmt.Sprintf("/v2/sharedkeys/%s", sharedKeyID)
	resp, err := h.request("DELETE", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteSharedKey response: %w", err)
	}
	return &result, nil
}

type DeleteSharedKeyOption func(*deleteSharedKeyOptions)
type deleteSharedKeyOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithDeleteSharedKeyToken(token string) DeleteSharedKeyOption {
	return func(o *deleteSharedKeyOptions) {
		o.token = token
	}
}
func WithDeleteSharedKeyFields(fields []string) DeleteSharedKeyOption {
	return func(o *deleteSharedKeyOptions) {
		o.fields = fields
	}
}

// --- Stats Endpoints ---

// GetImageStatsTotals retrieves total image generation statistics.
// GET /v2/stats/img/totals
func (h *AIHorde) GetImageStatsTotals(options ...GetImageStatsTotalsOption) (*StatsImgTotals, error) {
	opts := &getImageStatsTotalsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	// No token needed
	resp, err := h.request("GET", "/v2/stats/img/totals", WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var stats StatsImgTotals
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode GetImageStatsTotals response: %w", err)
	}
	return &stats, nil
}

type GetImageStatsTotalsOption func(*getImageStatsTotalsOptions)
type getImageStatsTotalsOptions struct {
	fields []string
}

func WithImageStatsTotalsFields(fields []string) GetImageStatsTotalsOption {
	return func(o *getImageStatsTotalsOptions) {
		o.fields = fields
	}
}

// GetImageStatsModels retrieves image generation statistics per model.
// GET /v2/stats/img/models
func (h *AIHorde) GetImageStatsModels(options ...GetImageStatsModelsOption) (*ImgModelStats, error) {
	opts := &getImageStatsModelsOptions{
		modelState: ModelStateKnown, // Default state
	}
	for _, opt := range options {
		opt(opts)
	}

	requestOptions := []RequestOption{WithFields(opts.fields)}
	requestOptions = append(requestOptions, WithQueryParam("model_state", string(opts.modelState)))

	// No token needed
	resp, err := h.request("GET", "/v2/stats/img/models", requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var stats ImgModelStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode GetImageStatsModels response: %w", err)
	}
	return &stats, nil
}

type GetImageStatsModelsOption func(*getImageStatsModelsOptions)
type getImageStatsModelsOptions struct {
	modelState ModelStateType
	fields     []string
}

func WithImageStatsModelsState(state ModelStateType) GetImageStatsModelsOption {
	return func(o *getImageStatsModelsOptions) {
		o.modelState = state
	}
}
func WithImageStatsModelsFields(fields []string) GetImageStatsModelsOption {
	return func(o *getImageStatsModelsOptions) {
		o.fields = fields
	}
}

// GetTextStatsTotals retrieves total text generation statistics.
// GET /v2/stats/text/totals
func (h *AIHorde) GetTextStatsTotals(options ...GetTextStatsTotalsOption) (*StatsTxtTotals, error) {
	opts := &getTextStatsTotalsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	// No token needed
	resp, err := h.request("GET", "/v2/stats/text/totals", WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var stats StatsTxtTotals
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode GetTextStatsTotals response: %w", err)
	}
	return &stats, nil
}

type GetTextStatsTotalsOption func(*getTextStatsTotalsOptions)
type getTextStatsTotalsOptions struct {
	fields []string
}

func WithTextStatsTotalsFields(fields []string) GetTextStatsTotalsOption {
	return func(o *getTextStatsTotalsOptions) {
		o.fields = fields
	}
}

// GetTextStatsModels retrieves text generation statistics per model.
// GET /v2/stats/text/models
func (h *AIHorde) GetTextStatsModels(options ...GetTextStatsModelsOption) (*TxtModelStats, error) {
	opts := &getTextStatsModelsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	// No token needed
	resp, err := h.request("GET", "/v2/stats/text/models", WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var stats TxtModelStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode GetTextStatsModels response: %w", err)
	}
	return &stats, nil
}

type GetTextStatsModelsOption func(*getTextStatsModelsOptions)
type getTextStatsModelsOptions struct {
	fields []string
}

func WithTextStatsModelsFields(fields []string) GetTextStatsModelsOption {
	return func(o *getTextStatsModelsOptions) {
		o.fields = fields
	}
}

// --- Heartbeat Endpoint ---

// GetHeartbeat checks if the horde node is available.
// GET /v2/status/heartbeat
func (h *AIHorde) GetHeartbeat() error {
	// No options needed, returns 200 on success, error otherwise
	resp, err := h.request("GET", "/v2/status/heartbeat")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Status code check is handled in request()
	return nil
}

// --- Style Endpoints ---

// GetImageStyles retrieves a list of image styles.
// GET /v2/styles/image
func (h *AIHorde) GetImageStyles(options ...GetImageStylesOption) ([]StyleStable, error) {
	opts := &getImageStylesOptions{
		page: 1,
		sort: SortPopular, // Default sort
	}
	for _, opt := range options {
		opt(opts)
	}

	requestOptions := []RequestOption{WithFields(opts.fields)}
	requestOptions = append(requestOptions, WithQueryParam("page", strconv.Itoa(opts.page)))
	requestOptions = append(requestOptions, WithQueryParam("sort", string(opts.sort)))
	if opts.tag != "" {
		requestOptions = append(requestOptions, WithQueryParam("tag", opts.tag))
	}
	if opts.model != "" {
		requestOptions = append(requestOptions, WithQueryParam("model", opts.model))
	}

	// No token needed
	resp, err := h.request("GET", "/v2/styles/image", requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var styles []StyleStable
	if err := json.NewDecoder(resp.Body).Decode(&styles); err != nil {
		return nil, fmt.Errorf("failed to decode GetImageStyles response: %w", err)
	}
	return styles, nil
}

type GetImageStylesOption func(*getImageStylesOptions)
type getImageStylesOptions struct {
	page   int
	sort   SortType
	tag    string // Optional filter
	model  string // Optional filter
	fields []string
}

func WithImageStylesPage(page int) GetImageStylesOption {
	return func(o *getImageStylesOptions) {
		if page > 0 {
			o.page = page
		}
	}
}
func WithImageStylesSort(sort SortType) GetImageStylesOption {
	return func(o *getImageStylesOptions) {
		o.sort = sort
	}
}
func WithImageStylesTag(tag string) GetImageStylesOption {
	return func(o *getImageStylesOptions) {
		o.tag = tag
	}
}
func WithImageStylesModel(model string) GetImageStylesOption {
	return func(o *getImageStylesOptions) {
		o.model = model
	}
}
func WithImageStylesFields(fields []string) GetImageStylesOption {
	return func(o *getImageStylesOptions) {
		o.fields = fields
	}
}

// CreateImageStyle creates a new image style.
// POST /v2/styles/image
func (h *AIHorde) CreateImageStyle(input ModelStyleInputStable, options ...CreateImageStyleOption) (*StyleModify, error) {
	opts := &createImageStyleOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for CreateImageStyle")
	}

	resp, err := h.request("POST", "/v2/styles/image", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result StyleModify
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CreateImageStyle response: %w", err)
	}
	return &result, nil
}

type CreateImageStyleOption func(*createImageStyleOptions)
type createImageStyleOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithCreateImageStyleToken(token string) CreateImageStyleOption {
	return func(o *createImageStyleOptions) {
		o.token = token
	}
}
func WithCreateImageStyleFields(fields []string) CreateImageStyleOption {
	return func(o *createImageStyleOptions) {
		o.fields = fields
	}
}

// GetImageStyleDetails retrieves details for a specific image style.
// GET /v2/styles/image/{style_id}
func (h *AIHorde) GetImageStyleDetails(styleID string, options ...GetImageStyleDetailsOption) (*StyleStable, error) {
	opts := &getImageStyleDetailsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/styles/image/%s", styleID)
	// No token needed
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var style StyleStable
	if err := json.NewDecoder(resp.Body).Decode(&style); err != nil {
		return nil, fmt.Errorf("failed to decode GetImageStyleDetails response: %w", err)
	}
	return &style, nil
}

type GetImageStyleDetailsOption func(*getImageStyleDetailsOptions)
type getImageStyleDetailsOptions struct {
	fields []string
}

func WithGetImageStyleDetailsFields(fields []string) GetImageStyleDetailsOption {
	return func(o *getImageStyleDetailsOptions) {
		o.fields = fields
	}
}

// ModifyImageStyle modifies an existing image style.
// PATCH /v2/styles/image/{style_id}
func (h *AIHorde) ModifyImageStyle(styleID string, input ModelStylePatchStable, options ...ModifyImageStyleOption) (*StyleModify, error) {
	opts := &modifyImageStyleOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for ModifyImageStyle")
	}

	path := fmt.Sprintf("/v2/styles/image/%s", styleID)
	resp, err := h.request("PATCH", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result StyleModify
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ModifyImageStyle response: %w", err)
	}
	return &result, nil
}

type ModifyImageStyleOption func(*modifyImageStyleOptions)
type modifyImageStyleOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithModifyImageStyleToken(token string) ModifyImageStyleOption {
	return func(o *modifyImageStyleOptions) {
		o.token = token
	}
}
func WithModifyImageStyleFields(fields []string) ModifyImageStyleOption {
	return func(o *modifyImageStyleOptions) {
		o.fields = fields
	}
}

// DeleteImageStyle deletes an image style (Mod only).
// DELETE /v2/styles/image/{style_id}
func (h *AIHorde) DeleteImageStyle(styleID string, options ...DeleteImageStyleOption) (*SimpleResponse, error) {
	opts := &deleteImageStyleOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for DeleteImageStyle")
	}

	path := fmt.Sprintf("/v2/styles/image/%s", styleID)
	resp, err := h.request("DELETE", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteImageStyle response: %w", err)
	}
	return &result, nil
}

type DeleteImageStyleOption func(*deleteImageStyleOptions)
type deleteImageStyleOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithDeleteImageStyleToken(token string) DeleteImageStyleOption {
	return func(o *deleteImageStyleOptions) {
		o.token = token
	}
}
func WithDeleteImageStyleFields(fields []string) DeleteImageStyleOption {
	return func(o *deleteImageStyleOptions) {
		o.fields = fields
	}
}

// CreateImageStyleExample adds an example image to an image style.
// POST /v2/styles/image/{style_id}/example
func (h *AIHorde) CreateImageStyleExample(styleID string, input InputStyleExamplePost, options ...CreateImageStyleExampleOption) (*StyleModify, error) {
	opts := &createImageStyleExampleOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for CreateImageStyleExample")
	}

	path := fmt.Sprintf("/v2/styles/image/%s/example", styleID)
	resp, err := h.request("POST", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result StyleModify
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CreateImageStyleExample response: %w", err)
	}
	return &result, nil
}

type CreateImageStyleExampleOption func(*createImageStyleExampleOptions)
type createImageStyleExampleOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithCreateImageStyleExampleToken(token string) CreateImageStyleExampleOption {
	return func(o *createImageStyleExampleOptions) {
		o.token = token
	}
}
func WithCreateImageStyleExampleFields(fields []string) CreateImageStyleExampleOption {
	return func(o *createImageStyleExampleOptions) {
		o.fields = fields
	}
}

// ModifyImageStyleExample modifies an existing image style example.
// PATCH /v2/styles/image/{style_id}/example/{example_id}
func (h *AIHorde) ModifyImageStyleExample(styleID, exampleID string, input InputStyleExamplePost, options ...ModifyImageStyleExampleOption) (*StyleModify, error) {
	opts := &modifyImageStyleExampleOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for ModifyImageStyleExample")
	}

	path := fmt.Sprintf("/v2/styles/image/%s/example/%s", styleID, exampleID)
	resp, err := h.request("PATCH", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result StyleModify
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ModifyImageStyleExample response: %w", err)
	}
	return &result, nil
}

type ModifyImageStyleExampleOption func(*modifyImageStyleExampleOptions)
type modifyImageStyleExampleOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithModifyImageStyleExampleToken(token string) ModifyImageStyleExampleOption {
	return func(o *modifyImageStyleExampleOptions) {
		o.token = token
	}
}
func WithModifyImageStyleExampleFields(fields []string) ModifyImageStyleExampleOption {
	return func(o *modifyImageStyleExampleOptions) {
		o.fields = fields
	}
}

// DeleteImageStyleExample deletes an image style example (Mod only).
// DELETE /v2/styles/image/{style_id}/example/{example_id}
func (h *AIHorde) DeleteImageStyleExample(styleID, exampleID string, options ...DeleteImageStyleExampleOption) (*SimpleResponse, error) {
	opts := &deleteImageStyleExampleOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for DeleteImageStyleExample")
	}

	path := fmt.Sprintf("/v2/styles/image/%s/example/%s", styleID, exampleID)
	resp, err := h.request("DELETE", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteImageStyleExample response: %w", err)
	}
	return &result, nil
}

type DeleteImageStyleExampleOption func(*deleteImageStyleExampleOptions)
type deleteImageStyleExampleOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithDeleteImageStyleExampleToken(token string) DeleteImageStyleExampleOption {
	return func(o *deleteImageStyleExampleOptions) {
		o.token = token
	}
}
func WithDeleteImageStyleExampleFields(fields []string) DeleteImageStyleExampleOption {
	return func(o *deleteImageStyleExampleOptions) {
		o.fields = fields
	}
}

// GetImageStyleByName retrieves details for a specific image style by name.
// GET /v2/styles/image_by_name/{style_name}
func (h *AIHorde) GetImageStyleByName(styleName string, options ...GetImageStyleByNameOption) (*StyleStable, error) {
	opts := &getImageStyleByNameOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/styles/image_by_name/%s", styleName) // Consider url.PathEscape
	// No token needed
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var style StyleStable
	if err := json.NewDecoder(resp.Body).Decode(&style); err != nil {
		return nil, fmt.Errorf("failed to decode GetImageStyleByName response: %w", err)
	}
	return &style, nil
}

type GetImageStyleByNameOption func(*getImageStyleByNameOptions)
type getImageStyleByNameOptions struct {
	fields []string
}

func WithGetImageStyleByNameFields(fields []string) GetImageStyleByNameOption {
	return func(o *getImageStyleByNameOptions) {
		o.fields = fields
	}
}

// GetTextStyles retrieves a list of text styles.
// GET /v2/styles/text
func (h *AIHorde) GetTextStyles(options ...GetTextStylesOption) ([]StyleKobold, error) {
	opts := &getTextStylesOptions{
		page: 1,
		sort: SortPopular, // Default sort
	}
	for _, opt := range options {
		opt(opts)
	}

	requestOptions := []RequestOption{WithFields(opts.fields)}
	requestOptions = append(requestOptions, WithQueryParam("page", strconv.Itoa(opts.page)))
	requestOptions = append(requestOptions, WithQueryParam("sort", string(opts.sort)))
	if opts.tag != "" {
		requestOptions = append(requestOptions, WithQueryParam("tag", opts.tag))
	}
	if opts.model != "" {
		requestOptions = append(requestOptions, WithQueryParam("model", opts.model))
	}

	// No token needed
	resp, err := h.request("GET", "/v2/styles/text", requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var styles []StyleKobold
	if err := json.NewDecoder(resp.Body).Decode(&styles); err != nil {
		return nil, fmt.Errorf("failed to decode GetTextStyles response: %w", err)
	}
	return styles, nil
}

type GetTextStylesOption func(*getTextStylesOptions)
type getTextStylesOptions struct {
	page   int
	sort   SortType
	tag    string // Optional filter
	model  string // Optional filter
	fields []string
}

func WithTextStylesPage(page int) GetTextStylesOption {
	return func(o *getTextStylesOptions) {
		if page > 0 {
			o.page = page
		}
	}
}
func WithTextStylesSort(sort SortType) GetTextStylesOption {
	return func(o *getTextStylesOptions) {
		o.sort = sort
	}
}
func WithTextStylesTag(tag string) GetTextStylesOption {
	return func(o *getTextStylesOptions) {
		o.tag = tag
	}
}
func WithTextStylesModel(model string) GetTextStylesOption {
	return func(o *getTextStylesOptions) {
		o.model = model
	}
}
func WithTextStylesFields(fields []string) GetTextStylesOption {
	return func(o *getTextStylesOptions) {
		o.fields = fields
	}
}

// CreateTextStyle creates a new text style.
// POST /v2/styles/text
func (h *AIHorde) CreateTextStyle(input ModelStyleInputKobold, options ...CreateTextStyleOption) (*StyleModify, error) {
	opts := &createTextStyleOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for CreateTextStyle")
	}

	resp, err := h.request("POST", "/v2/styles/text", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result StyleModify
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CreateTextStyle response: %w", err)
	}
	return &result, nil
}

type CreateTextStyleOption func(*createTextStyleOptions)
type createTextStyleOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithCreateTextStyleToken(token string) CreateTextStyleOption {
	return func(o *createTextStyleOptions) {
		o.token = token
	}
}
func WithCreateTextStyleFields(fields []string) CreateTextStyleOption {
	return func(o *createTextStyleOptions) {
		o.fields = fields
	}
}

// GetTextStyleDetails retrieves details for a specific text style.
// GET /v2/styles/text/{style_id}
func (h *AIHorde) GetTextStyleDetails(styleID string, options ...GetTextStyleDetailsOption) (*StyleKobold, error) {
	opts := &getTextStyleDetailsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/styles/text/%s", styleID)
	// No token needed
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var style StyleKobold
	if err := json.NewDecoder(resp.Body).Decode(&style); err != nil {
		return nil, fmt.Errorf("failed to decode GetTextStyleDetails response: %w", err)
	}
	return &style, nil
}

type GetTextStyleDetailsOption func(*getTextStyleDetailsOptions)
type getTextStyleDetailsOptions struct {
	fields []string
}

func WithGetTextStyleDetailsFields(fields []string) GetTextStyleDetailsOption {
	return func(o *getTextStyleDetailsOptions) {
		o.fields = fields
	}
}

// ModifyTextStyle modifies an existing text style.
// PATCH /v2/styles/text/{style_id}
func (h *AIHorde) ModifyTextStyle(styleID string, input ModelStylePatchKobold, options ...ModifyTextStyleOption) (*StyleModify, error) {
	opts := &modifyTextStyleOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for ModifyTextStyle")
	}

	path := fmt.Sprintf("/v2/styles/text/%s", styleID)
	resp, err := h.request("PATCH", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result StyleModify
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ModifyTextStyle response: %w", err)
	}
	return &result, nil
}

type ModifyTextStyleOption func(*modifyTextStyleOptions)
type modifyTextStyleOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithModifyTextStyleToken(token string) ModifyTextStyleOption {
	return func(o *modifyTextStyleOptions) {
		o.token = token
	}
}
func WithModifyTextStyleFields(fields []string) ModifyTextStyleOption {
	return func(o *modifyTextStyleOptions) {
		o.fields = fields
	}
}

// DeleteTextStyle deletes a text style (Mod only).
// DELETE /v2/styles/text/{style_id}
func (h *AIHorde) DeleteTextStyle(styleID string, options ...DeleteTextStyleOption) (*SimpleResponse, error) {
	opts := &deleteTextStyleOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("moderator API key is required for DeleteTextStyle")
	}

	path := fmt.Sprintf("/v2/styles/text/%s", styleID)
	resp, err := h.request("DELETE", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteTextStyle response: %w", err)
	}
	return &result, nil
}

type DeleteTextStyleOption func(*deleteTextStyleOptions)
type deleteTextStyleOptions struct {
	token  string // Required: Mod API key
	fields []string
}

func WithDeleteTextStyleToken(token string) DeleteTextStyleOption {
	return func(o *deleteTextStyleOptions) {
		o.token = token
	}
}
func WithDeleteTextStyleFields(fields []string) DeleteTextStyleOption {
	return func(o *deleteTextStyleOptions) {
		o.fields = fields
	}
}

// GetTextStyleByName retrieves details for a specific text style by name.
// GET /v2/styles/text_by_name/{style_name}
func (h *AIHorde) GetTextStyleByName(styleName string, options ...GetTextStyleByNameOption) (*StyleKobold, error) {
	opts := &getTextStyleByNameOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/styles/text_by_name/%s", styleName) // Consider url.PathEscape
	// No token needed
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var style StyleKobold
	if err := json.NewDecoder(resp.Body).Decode(&style); err != nil {
		return nil, fmt.Errorf("failed to decode GetTextStyleByName response: %w", err)
	}
	return &style, nil
}

type GetTextStyleByNameOption func(*getTextStyleByNameOptions)
type getTextStyleByNameOptions struct {
	fields []string
}

func WithGetTextStyleByNameFields(fields []string) GetTextStyleByNameOption {
	return func(o *getTextStyleByNameOptions) {
		o.fields = fields
	}
}

// --- Team Endpoints ---

// GetTeams retrieves a list of all teams.
// GET /v2/teams
func (h *AIHorde) GetTeams(options ...GetTeamsOption) ([]TeamDetails, error) {
	opts := &getTeamsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	// No token needed
	resp, err := h.request("GET", "/v2/teams", WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var teams []TeamDetails
	if err := json.NewDecoder(resp.Body).Decode(&teams); err != nil {
		return nil, fmt.Errorf("failed to decode GetTeams response: %w", err)
	}
	return teams, nil
}

type GetTeamsOption func(*getTeamsOptions)
type getTeamsOptions struct {
	fields []string
}

func WithGetTeamsFields(fields []string) GetTeamsOption {
	return func(o *getTeamsOptions) {
		o.fields = fields
	}
}

// CreateTeam creates a new team (Trusted users only).
// POST /v2/teams
func (h *AIHorde) CreateTeam(input CreateTeamInput, options ...CreateTeamOption) (*ModifyTeam, error) {
	opts := &createTeamOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("API key is required for CreateTeam")
	}

	resp, err := h.request("POST", "/v2/teams", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ModifyTeam
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CreateTeam response: %w", err)
	}
	return &result, nil
}

type CreateTeamOption func(*createTeamOptions)
type createTeamOptions struct {
	token  string // Required: User API key (must be trusted)
	fields []string
}

func WithCreateTeamToken(token string) CreateTeamOption {
	return func(o *createTeamOptions) {
		o.token = token
	}
}
func WithCreateTeamFields(fields []string) CreateTeamOption {
	return func(o *createTeamOptions) {
		o.fields = fields
	}
}

// GetTeamDetails retrieves details for a specific team.
// GET /v2/teams/{team_id}
func (h *AIHorde) GetTeamDetails(teamID string, options ...GetTeamDetailsOption) (*TeamDetails, error) {
	opts := &getTeamDetailsOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/teams/%s", teamID)
	// Token optional for privileged info
	resp, err := h.request("GET", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var team TeamDetails
	if err := json.NewDecoder(resp.Body).Decode(&team); err != nil {
		return nil, fmt.Errorf("failed to decode GetTeamDetails response: %w", err)
	}
	return &team, nil
}

type GetTeamDetailsOption func(*getTeamDetailsOptions)
type getTeamDetailsOptions struct {
	token  string // Optional: Moderator or Owner API key
	fields []string
}

func WithGetTeamDetailsToken(token string) GetTeamDetailsOption {
	return func(o *getTeamDetailsOptions) {
		o.token = token
	}
}
func WithGetTeamDetailsFields(fields []string) GetTeamDetailsOption {
	return func(o *getTeamDetailsOptions) {
		o.fields = fields
	}
}

// ModifyTeam updates a team's information (Creator or Mod only).
// PATCH /v2/teams/{team_id}
func (h *AIHorde) ModifyTeam(teamID string, input ModifyTeamInput, options ...ModifyTeamOption) (*ModifyTeam, error) {
	opts := &modifyTeamOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Creator or Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("creator or moderator API key is required for ModifyTeam")
	}

	path := fmt.Sprintf("/v2/teams/%s", teamID)
	resp, err := h.request("PATCH", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ModifyTeam
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ModifyTeam response: %w", err)
	}
	return &result, nil
}

type ModifyTeamOption func(*modifyTeamOptions)
type modifyTeamOptions struct {
	token  string // Required: Creator or Mod API key
	fields []string
}

func WithModifyTeamToken(token string) ModifyTeamOption {
	return func(o *modifyTeamOptions) {
		o.token = token
	}
}
func WithModifyTeamFields(fields []string) ModifyTeamOption {
	return func(o *modifyTeamOptions) {
		o.fields = fields
	}
}

// DeleteTeam deletes a team (Creator or Mod only).
// DELETE /v2/teams/{team_id}
func (h *AIHorde) DeleteTeam(teamID string, options ...DeleteTeamOption) (*DeletedTeam, error) {
	opts := &deleteTeamOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Creator or Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("creator or moderator API key is required for DeleteTeam")
	}

	path := fmt.Sprintf("/v2/teams/%s", teamID)
	resp, err := h.request("DELETE", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result DeletedTeam
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteTeam response: %w", err)
	}
	return &result, nil
}

type DeleteTeamOption func(*deleteTeamOptions)
type deleteTeamOptions struct {
	token  string // Required: Creator or Mod API key
	fields []string
}

func WithDeleteTeamToken(token string) DeleteTeamOption {
	return func(o *deleteTeamOptions) {
		o.token = token
	}
}
func WithDeleteTeamFields(fields []string) DeleteTeamOption {
	return func(o *deleteTeamOptions) {
		o.fields = fields
	}
}

// --- Worker Endpoints ---

// GetWorkers retrieves a list of registered and active workers.
// GET /v2/workers
func (h *AIHorde) GetWorkers(options ...GetWorkersOption) ([]WorkerDetails, error) {
	opts := &getWorkersOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}

	requestOptions := []RequestOption{WithToken(opts.token), WithFields(opts.fields)} // Token optional for mod info
	if opts.workerType != "" {
		requestOptions = append(requestOptions, WithQueryParam("type", string(opts.workerType)))
	}
	if opts.name != "" {
		requestOptions = append(requestOptions, WithQueryParam("name", opts.name))
	}

	resp, err := h.request("GET", "/v2/workers", requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var workers []WorkerDetails
	if err := json.NewDecoder(resp.Body).Decode(&workers); err != nil {
		return nil, fmt.Errorf("failed to decode GetWorkers response: %w", err)
	}
	return workers, nil
}

type GetWorkersOption func(*getWorkersOptions)
type getWorkersOptions struct {
	token      string    // Optional: Moderator API key for more details
	workerType ModelType // Optional filter: image, text, interrogation
	name       string    // Optional filter
	fields     []string
}

func WithGetWorkersToken(token string) GetWorkersOption {
	return func(o *getWorkersOptions) {
		o.token = token
	}
}
func WithGetWorkersType(workerType ModelType) GetWorkersOption {
	return func(o *getWorkersOptions) {
		o.workerType = workerType
	}
}
func WithGetWorkersName(name string) GetWorkersOption {
	return func(o *getWorkersOptions) {
		o.name = name
	}
}
func WithGetWorkersFields(fields []string) GetWorkersOption {
	return func(o *getWorkersOptions) {
		o.fields = fields
	}
}

// GetWorkerMessages retrieves messages intended for workers.
// GET /v2/workers/messages
func (h *AIHorde) GetWorkerMessages(options ...GetWorkerMessagesOption) ([]ResponseModelMessage, error) {
	opts := &getWorkerMessagesOptions{
		validity: ValidityActive, // Default validity
		page:     1,              // Default page
	}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("user API key is required for GetWorkerMessages")
	}

	requestOptions := []RequestOption{WithToken(opts.token), WithFields(opts.fields)}
	if opts.userID != "" {
		requestOptions = append(requestOptions, WithQueryParam("user_id", opts.userID))
	}
	if opts.workerID != "" {
		requestOptions = append(requestOptions, WithQueryParam("worker_id", opts.workerID))
	}
	requestOptions = append(requestOptions, WithQueryParam("validity", string(opts.validity)))
	requestOptions = append(requestOptions, WithQueryParam("page", strconv.Itoa(opts.page)))

	resp, err := h.request("GET", "/v2/workers/messages", requestOptions...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var messages []ResponseModelMessage
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		return nil, fmt.Errorf("failed to decode GetWorkerMessages response: %w", err)
	}
	return messages, nil
}

type GetWorkerMessagesOption func(*getWorkerMessagesOptions)
type getWorkerMessagesOptions struct {
	token    string             // Required: User API key
	userID   string             // Optional filter
	workerID string             // Optional filter
	validity FilterValidityType // Optional filter (active, expired, all)
	page     int                // Optional pagination
	fields   []string
}

func WithGetWorkerMessagesToken(token string) GetWorkerMessagesOption {
	return func(o *getWorkerMessagesOptions) {
		o.token = token
	}
}
func WithGetWorkerMessagesUserID(userID string) GetWorkerMessagesOption {
	return func(o *getWorkerMessagesOptions) {
		o.userID = userID
	}
}
func WithGetWorkerMessagesWorkerID(workerID string) GetWorkerMessagesOption {
	return func(o *getWorkerMessagesOptions) {
		o.workerID = workerID
	}
}
func WithGetWorkerMessagesValidity(validity FilterValidityType) GetWorkerMessagesOption {
	return func(o *getWorkerMessagesOptions) {
		o.validity = validity
	}
}
func WithGetWorkerMessagesPage(page int) GetWorkerMessagesOption {
	return func(o *getWorkerMessagesOptions) {
		if page > 0 {
			o.page = page
		}
	}
}
func WithGetWorkerMessagesFields(fields []string) GetWorkerMessagesOption {
	return func(o *getWorkerMessagesOptions) {
		o.fields = fields
	}
}

// CreateWorkerMessage creates a new message for a worker.
// POST /v2/workers/messages
func (h *AIHorde) CreateWorkerMessage(input ResponseModelMessage, options ...CreateWorkerMessageOption) (*ResponseModelMessage, error) {
	opts := &createWorkerMessageOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("user API key is required for CreateWorkerMessage")
	}

	resp, err := h.request("POST", "/v2/workers/messages", WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ResponseModelMessage
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CreateWorkerMessage response: %w", err)
	}
	return &result, nil
}

type CreateWorkerMessageOption func(*createWorkerMessageOptions)
type createWorkerMessageOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithCreateWorkerMessageToken(token string) CreateWorkerMessageOption {
	return func(o *createWorkerMessageOptions) {
		o.token = token
	}
}
func WithCreateWorkerMessageFields(fields []string) CreateWorkerMessageOption {
	return func(o *createWorkerMessageOptions) {
		o.fields = fields
	}
}

// GetWorkerMessageDetails retrieves details for a specific worker message.
// GET /v2/workers/messages/{message_id}
func (h *AIHorde) GetWorkerMessageDetails(messageID string, options ...GetWorkerMessageDetailsOption) (*ResponseModelMessage, error) {
	opts := &getWorkerMessageDetailsOptions{}
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/workers/messages/%s", messageID)
	// No token needed? Spec doesn't list one. Assumes public read or implicitly uses default token if set.
	resp, err := h.request("GET", path, WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var message ResponseModelMessage
	if err := json.NewDecoder(resp.Body).Decode(&message); err != nil {
		return nil, fmt.Errorf("failed to decode GetWorkerMessageDetails response: %w", err)
	}
	return &message, nil
}

type GetWorkerMessageDetailsOption func(*getWorkerMessageDetailsOptions)
type getWorkerMessageDetailsOptions struct {
	fields []string
}

func WithGetWorkerMessageDetailsFields(fields []string) GetWorkerMessageDetailsOption {
	return func(o *getWorkerMessageDetailsOptions) {
		o.fields = fields
	}
}

// DeleteWorkerMessage deletes a specific worker message.
// DELETE /v2/workers/messages/{message_id}
func (h *AIHorde) DeleteWorkerMessage(messageID string, options ...DeleteWorkerMessageOption) (*SimpleResponse, error) {
	opts := &deleteWorkerMessageOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// User token is required
	if opts.token == "" {
		return nil, fmt.Errorf("user API key is required for DeleteWorkerMessage")
	}

	path := fmt.Sprintf("/v2/workers/messages/%s", messageID)
	resp, err := h.request("DELETE", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SimpleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteWorkerMessage response: %w", err)
	}
	return &result, nil
}

type DeleteWorkerMessageOption func(*deleteWorkerMessageOptions)
type deleteWorkerMessageOptions struct {
	token  string // Required: User API key
	fields []string
}

func WithDeleteWorkerMessageToken(token string) DeleteWorkerMessageOption {
	return func(o *deleteWorkerMessageOptions) {
		o.token = token
	}
}
func WithDeleteWorkerMessageFields(fields []string) DeleteWorkerMessageOption {
	return func(o *deleteWorkerMessageOptions) {
		o.fields = fields
	}
}

// GetWorkerDetails retrieves details for a specific worker by ID.
// GET /v2/workers/{worker_id}
func (h *AIHorde) GetWorkerDetails(workerID string, options ...GetWorkerDetailsOption) (*WorkerDetails, error) {
	opts := &getWorkerDetailsOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/workers/%s", workerID)
	// Token optional for privileged info
	resp, err := h.request("GET", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var worker WorkerDetails
	if err := json.NewDecoder(resp.Body).Decode(&worker); err != nil {
		return nil, fmt.Errorf("failed to decode GetWorkerDetails response: %w", err)
	}
	return &worker, nil
}

type GetWorkerDetailsOption func(*getWorkerDetailsOptions)
type getWorkerDetailsOptions struct {
	token  string // Optional: Moderator or Owner API key
	fields []string
}

func WithGetWorkerDetailsToken(token string) GetWorkerDetailsOption {
	return func(o *getWorkerDetailsOptions) {
		o.token = token
	}
}
func WithGetWorkerDetailsFields(fields []string) GetWorkerDetailsOption {
	return func(o *getWorkerDetailsOptions) {
		o.fields = fields
	}
}

// ModifyWorker updates details for a specific worker (Owner or Mod only).
// PUT /v2/workers/{worker_id}
func (h *AIHorde) ModifyWorker(workerID string, input ModifyWorkerInput, options ...ModifyWorkerOption) (*ModifyWorker, error) {
	opts := &modifyWorkerOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Owner or Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("owner or moderator API key is required for ModifyWorker")
	}

	path := fmt.Sprintf("/v2/workers/%s", workerID)
	resp, err := h.request("PUT", path, WithToken(opts.token), WithFields(opts.fields), WithBody(input))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ModifyWorker
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ModifyWorker response: %w", err)
	}
	return &result, nil
}

type ModifyWorkerOption func(*modifyWorkerOptions)
type modifyWorkerOptions struct {
	token  string // Required: Owner or Mod API key
	fields []string
}

func WithModifyWorkerToken(token string) ModifyWorkerOption {
	return func(o *modifyWorkerOptions) {
		o.token = token
	}
}
func WithModifyWorkerFields(fields []string) ModifyWorkerOption {
	return func(o *modifyWorkerOptions) {
		o.fields = fields
	}
}

// DeleteWorker deletes a specific worker (Owner or Mod only).
// DELETE /v2/workers/{worker_id}
func (h *AIHorde) DeleteWorker(workerID string, options ...DeleteWorkerOption) (*DeletedWorker, error) {
	opts := &deleteWorkerOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}
	// Owner or Mod token is required
	if opts.token == "" {
		return nil, fmt.Errorf("owner or moderator API key is required for DeleteWorker")
	}

	path := fmt.Sprintf("/v2/workers/%s", workerID)
	resp, err := h.request("DELETE", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result DeletedWorker
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode DeleteWorker response: %w", err)
	}
	return &result, nil
}

type DeleteWorkerOption func(*deleteWorkerOptions)
type deleteWorkerOptions struct {
	token  string // Required: Owner or Mod API key
	fields []string
}

func WithDeleteWorkerToken(token string) DeleteWorkerOption {
	return func(o *deleteWorkerOptions) {
		o.token = token
	}
}
func WithDeleteWorkerFields(fields []string) DeleteWorkerOption {
	return func(o *deleteWorkerOptions) {
		o.fields = fields
	}
}

// GetWorkerDetailsByName retrieves details for a specific worker by name.
// GET /v2/workers/name/{worker_name}
func (h *AIHorde) GetWorkerDetailsByName(workerName string, options ...GetWorkerDetailsByNameOption) (*WorkerDetails, error) {
	opts := &getWorkerDetailsByNameOptions{}
	opts.token = h.defaultToken
	for _, opt := range options {
		opt(opts)
	}

	path := fmt.Sprintf("/v2/workers/name/%s", workerName) // Consider url.PathEscape
	// Token optional for privileged info
	resp, err := h.request("GET", path, WithToken(opts.token), WithFields(opts.fields))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var worker WorkerDetails
	if err := json.NewDecoder(resp.Body).Decode(&worker); err != nil {
		return nil, fmt.Errorf("failed to decode GetWorkerDetailsByName response: %w", err)
	}
	return &worker, nil
}

type GetWorkerDetailsByNameOption func(*getWorkerDetailsByNameOptions)
type getWorkerDetailsByNameOptions struct {
	token  string // Optional: Moderator or Owner API key
	fields []string
}

func WithGetWorkerDetailsByNameToken(token string) GetWorkerDetailsByNameOption {
	return func(o *getWorkerDetailsByNameOptions) {
		o.token = token
	}
}
func WithGetWorkerDetailsByNameFields(fields []string) GetWorkerDetailsByNameOption {
	return func(o *getWorkerDetailsByNameOptions) {
		o.fields = fields
	}
}
