package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

type Language struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func parseChoices(raw json.RawMessage, names map[string]string) ([]Language, error) {
	records, err := collection(raw)
	if err != nil {
		return nil, err
	}
	out := make([]Language, 0, len(records))
	seen := make(map[string]bool)
	for _, record := range records {
		var id string
		if json.Unmarshal(record, &id) != nil || validSelector("choice", id) != nil || seen[id] {
			return nil, fmt.Errorf("invalid or duplicate choice identifier")
		}
		seen[id] = true
		name := names[id]
		if name == "" {
			name = id
		}
		out = append(out, Language{ID: id, Name: name})
	}
	return out, nil
}

func parseLanguages(data []byte) ([]Language, error) {
	raw, err := decodeEnvelope(data, "listlangs.php", 200)
	if err != nil {
		return nil, err
	}
	var response struct {
		List  json.RawMessage   `json:"langList"`
		Names map[string]string `json:"langFancyNames"`
	}
	if json.Unmarshal(raw, &response) != nil {
		return nil, fmt.Errorf("catalog listlangs.php: invalid response")
	}
	out, err := parseChoices(response.List, response.Names)
	if err != nil {
		return nil, fmt.Errorf("catalog listlangs.php: %w", err)
	}
	return out, nil
}

func (c *Client) Languages(ctx context.Context, updateID string) ([]Language, error) {
	if err := validUpdateID(updateID); err != nil {
		return nil, err
	}
	return cached(ctx, c, "listlangs.php", url.Values{"id": {updateID}}, parseLanguages)
}
