package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"time"

	"uupbuilder/internal/model"
)

// Build retains the exact UUID/revision-qualified upstream identifier. Titles
// and build numbers are descriptions; they do not imply channel or grouping.
type Build struct {
	UpdateID     string             `json:"update_id"`
	Title        string             `json:"title"`
	Build        string             `json:"build"`
	Architecture model.Architecture `json:"architecture"`
	CreatedAt    time.Time          `json:"created_at"`
}

func numericRecords(records map[string]json.RawMessage) ([]json.RawMessage, error) {
	keys := make([]string, 0, len(records))
	for key := range records {
		if key == "" || strings.Trim(key, "0123456789") != "" {
			return nil, fmt.Errorf("invalid numeric collection key")
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, _ := new(big.Int).SetString(keys[i], 10)
		b, _ := new(big.Int).SetString(keys[j], 10)
		if n := a.Cmp(b); n != 0 {
			return n < 0
		}
		return keys[i] < keys[j]
	})
	out := make([]json.RawMessage, 0, len(keys))
	for _, key := range keys {
		out = append(out, records[key])
	}
	return out, nil
}

func parseBuilds(data []byte) ([]Build, error) {
	raw, err := decodeEnvelope(data, "listid.php", 200)
	if err != nil {
		return nil, err
	}
	var response struct {
		Builds json.RawMessage `json:"builds"`
	}
	if json.Unmarshal(raw, &response) != nil {
		return nil, fmt.Errorf("catalog listid.php: invalid response")
	}
	records, err := collection(response.Builds)
	if err != nil {
		return nil, fmt.Errorf("catalog listid.php: %w", err)
	}
	out := make([]Build, 0, len(records))
	seen := make(map[string]bool)
	for _, record := range records {
		var b struct {
			Title   string             `json:"title"`
			Build   string             `json:"build"`
			Arch    model.Architecture `json:"arch"`
			Created *int64             `json:"created"`
			UUID    string             `json:"uuid"`
		}
		if json.Unmarshal(record, &b) != nil || validUpdateID(b.UUID) != nil || b.Created == nil || *b.Created < 0 || strings.TrimSpace(b.Title) == "" || strings.TrimSpace(b.Build) == "" || b.Arch.Validate() != nil || seen[b.UUID] {
			return nil, fmt.Errorf("catalog listid.php: invalid or duplicate build record")
		}
		seen[b.UUID] = true
		out = append(out, Build{UpdateID: b.UUID, Title: b.Title, Build: b.Build, Architecture: b.Arch, CreatedAt: time.Unix(*b.Created, 0).UTC()})
	}
	return out, nil
}

func (c *Client) Search(ctx context.Context, query string) ([]Build, error) {
	return cached(ctx, c, "listid.php", url.Values{"search": {query}, "sortByDate": {"1"}}, parseBuilds)
}
