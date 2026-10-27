package probes

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"uupbuilder/internal/model"
)

func inspectCompDB(ctx context.Context, reader io.Reader) (CompDBIdentity, error) {
	const limit = 4 << 20
	var identity CompDBIdentity
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, reader}, limit+1))
	if err != nil {
		return identity, err
	}
	if len(data) > limit {
		return identity, errors.New("CompDB exceeds 4 MiB observation bound")
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	depth, roots, tokens := 0, 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return identity, err
		}
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return identity, err
		}
		tokens++
		if tokens > 100000 {
			return identity, errors.New("CompDB token bound exceeded")
		}
		switch t := token.(type) {
		case xml.Directive:
			return identity, errors.New("CompDB directives forbidden")
		case xml.ProcInst:
			if t.Target != "xml" || roots != 0 {
				return identity, errors.New("CompDB processing instruction forbidden")
			}
		case xml.StartElement:
			depth++
			if depth > 128 {
				return identity, errors.New("CompDB depth bound exceeded")
			}
			seen := map[xml.Name]bool{}
			attrs := map[string]string{}
			for _, a := range t.Attr {
				if seen[a.Name] {
					return identity, errors.New("duplicate XML attribute")
				}
				seen[a.Name] = true
				if a.Name.Space == "" {
					attrs[a.Name.Local] = a.Value
				}
			}
			if depth == 1 {
				roots++
				if roots != 1 || t.Name.Local != "CompDB" || t.Name.Space != "http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" {
					return identity, errors.New("one CompDB root in the expected namespace required")
				}
				identity = CompDBIdentity{Architecture: model.Architecture(attrs["BuildArch"]), Type: attrs["Type"], BuildID: attrs["BuildID"], OSVersion: attrs["OSVersion"]}
				if err := identity.Architecture.Validate(); err != nil {
					return identity, err
				}
				for _, v := range []string{identity.Type, identity.BuildID, identity.OSVersion} {
					if err := textRequired("CompDB identity", v); err != nil {
						return identity, err
					}
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return identity, errors.New("text outside CompDB root")
			}
		}
	}
	if roots != 1 || depth != 0 {
		return identity, errors.New("incomplete CompDB XML")
	}
	return identity, nil
}

func parseCertutilSHA256(text string) (string, error) {
	if len(text) > 64<<10 {
		return "", errors.New("certutil output exceeds retained log bound")
	}
	digest := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.ReplaceAll(strings.TrimSpace(line), " ", "")
		if len(line) != 64 {
			continue
		}
		if _, err := hex.DecodeString(line); err != nil {
			continue
		}
		if digest != "" {
			return "", errors.New("ambiguous independent SHA-256 output")
		}
		digest = strings.ToLower(line)
	}
	if digest == "" {
		return "", fmt.Errorf("independent SHA-256 not found in certutil output")
	}
	return digest, nil
}
