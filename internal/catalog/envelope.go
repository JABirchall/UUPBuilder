package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// APIError exposes a sanitized upstream error code and HTTP status. It never
// includes the response body or the request URL, which may contain private data.
type APIError struct {
	Endpoint   string
	StatusCode int
	Code       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("catalog %s: HTTP %d (%s)", e.Endpoint, e.StatusCode, e.Code)
}

var errorCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,95}$`)

func decodeEnvelope(data []byte, endpoint string, status int) (json.RawMessage, error) {
	var envelope struct {
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("catalog %s: malformed JSON envelope (HTTP %d)", endpoint, status)
	}
	var response map[string]json.RawMessage
	if len(envelope.Response) == 0 || json.Unmarshal(envelope.Response, &response) != nil || response == nil {
		return nil, fmt.Errorf("catalog %s: missing object response (HTTP %d)", endpoint, status)
	}
	if raw, exists := response["error"]; exists && string(raw) != "null" {
		var code string
		if json.Unmarshal(raw, &code) != nil || !errorCodePattern.MatchString(code) {
			code = "UPSTREAM_ERROR"
		}
		return nil, &APIError{Endpoint: endpoint, StatusCode: status, Code: code}
	}
	if status < 200 || status >= 300 {
		return nil, &APIError{Endpoint: endpoint, StatusCode: status, Code: "HTTP_ERROR"}
	}
	return envelope.Response, nil
}

// collection accepts PHP's array and numeric-keyed object encodings. Keys are
// ordering information only and never become a record identity.
func collection(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing collection")
	}
	switch raw[0] {
	case '[':
		var records []json.RawMessage
		err := json.Unmarshal(raw, &records)
		return records, err
	case '{':
		var records map[string]json.RawMessage
		if err := json.Unmarshal(raw, &records); err != nil {
			return nil, err
		}
		return numericRecords(records)
	default:
		return nil, errors.New("collection must be an array or numeric-keyed object")
	}
}
