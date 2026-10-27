package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"time"

	"uupbuilder/internal/model"
)

type FileSet struct {
	Source   model.SourceIdentity `json:"source"`
	Title    string               `json:"title"`
	Payloads []model.Payload      `json:"payloads"`
	Locators model.Locators       `json:"-" toml:"-"`
}

// wireInteger accepts the API's decimal strings and JSON integer forms, without
// floating point conversion or loss of size/expiry precision.
func wireInteger(raw json.RawMessage) (int64, error) {
	text := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &text); err != nil {
			return 0, err
		}
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("invalid nonnegative integer")
	}
	return value, nil
}

func parseFiles(data []byte, updateID, language string) (FileSet, error) {
	raw, err := decodeEnvelope(data, "get.php", 200)
	if err != nil {
		return FileSet{}, err
	}
	var response struct {
		Title string             `json:"updateName"`
		Arch  model.Architecture `json:"arch"`
		Build string             `json:"build"`
		Files map[string]struct {
			SHA1   *string         `json:"sha1"`
			SHA256 *string         `json:"sha256"`
			Size   json.RawMessage `json:"size"`
			URL    *string         `json:"url"`
			Expire json.RawMessage `json:"expire"`
		} `json:"files"`
	}
	if json.Unmarshal(raw, &response) != nil || len(response.Files) == 0 {
		return FileSet{}, fmt.Errorf("catalog get.php: missing or invalid file metadata")
	}
	source, err := model.NewSourceIdentity(updateID, response.Build, response.Arch, language)
	if err != nil {
		return FileSet{}, fmt.Errorf("catalog get.php: invalid source identity")
	}
	set := FileSet{Source: source, Title: response.Title, Locators: make(model.Locators)}
	names := make([]string, 0, len(response.Files))
	for name := range response.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		file := response.Files[name]
		algorithm := model.DigestSHA1
		value := file.SHA1
		if file.SHA256 != nil {
			algorithm = model.DigestSHA256
			value = file.SHA256
		}
		if value == nil {
			return FileSet{}, fmt.Errorf("catalog get.php: file lacks trusted digest metadata")
		}
		digest, err := model.NewDigest(algorithm, *value)
		if err != nil {
			return FileSet{}, fmt.Errorf("catalog get.php: invalid file digest")
		}
		// Validate SHA-1 too when supplied, even if stronger metadata is present.
		if file.SHA1 != nil {
			if _, err := model.NewDigest(model.DigestSHA1, *file.SHA1); err != nil {
				return FileSet{}, fmt.Errorf("catalog get.php: invalid SHA-1 metadata")
			}
		}
		size, err := wireInteger(file.Size)
		if err != nil {
			return FileSet{}, fmt.Errorf("catalog get.php: invalid file size")
		}
		// This is the resolver-returned logical name, not a claim to Microsoft's
		// original composition/package name. Later metadata inspection supplies it.
		identity := model.PayloadIdentity{Digest: digest, Size: size, Provenance: model.PackageProvenance{Source: "uupdump:get.php:" + updateID, Name: name}}
		payload, err := model.NewPayload(identity, name)
		if err != nil {
			return FileSet{}, fmt.Errorf("catalog get.php: invalid payload destination or identity")
		}
		set.Payloads = append(set.Payloads, payload)
		expiry, err := wireInteger(file.Expire)
		if err != nil {
			return FileSet{}, fmt.Errorf("catalog get.php: invalid locator expiry")
		}
		if file.URL == nil {
			continue
		}
		u, err := url.Parse(*file.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
			return FileSet{}, fmt.Errorf("catalog get.php: invalid HTTP(S) payload locator")
		}
		locator := model.Locator{URL: *file.URL}
		if expiry > 0 {
			locator.ExpiresAt = time.Unix(expiry, 0).UTC()
		}
		set.Locators[identity] = locator
	}
	if _, err := model.NewPayloadManifest(source, set.Payloads); err != nil {
		return FileSet{}, fmt.Errorf("catalog get.php: conflicting or invalid payload destinations")
	}
	return set, nil
}

func (c *Client) Files(ctx context.Context, updateID, language, edition string) (FileSet, error) {
	if err := validUpdateID(updateID); err != nil {
		return FileSet{}, err
	}
	if err := validSelector("language", language); err != nil {
		return FileSet{}, err
	}
	if err := validSelector("edition", edition); err != nil {
		return FileSet{}, err
	}
	noLinks := "0"
	if c.MetadataOnly {
		noLinks = "1"
	}
	data, err := c.fetch(ctx, "get.php", url.Values{"id": {updateID}, "lang": {language}, "edition": {edition}, "noLinks": {noLinks}})
	if err != nil {
		return FileSet{}, err
	}
	return parseFiles(data, updateID, language)
}
