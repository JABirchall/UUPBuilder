package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

type Edition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func parseEditions(data []byte) ([]Edition, error) {
	raw, err := decodeEnvelope(data, "listeditions.php", 200)
	if err != nil {
		return nil, err
	}
	var response struct {
		List  json.RawMessage   `json:"editionList"`
		Names map[string]string `json:"editionFancyNames"`
	}
	if json.Unmarshal(raw, &response) != nil {
		return nil, fmt.Errorf("catalog listeditions.php: invalid response")
	}
	choices, err := parseChoices(response.List, response.Names)
	if err != nil {
		return nil, fmt.Errorf("catalog listeditions.php: %w", err)
	}
	out := make([]Edition, 0, len(choices))
	for _, choice := range choices {
		out = append(out, Edition{ID: choice.ID, Name: choice.Name})
	}
	return out, nil
}

func (c *Client) Editions(ctx context.Context, updateID, language string) ([]Edition, error) {
	if err := validUpdateID(updateID); err != nil {
		return nil, err
	}
	if err := validSelector("language", language); err != nil {
		return nil, err
	}
	return cached(ctx, c, "listeditions.php", url.Values{"id": {updateID}, "lang": {language}}, parseEditions)
}
