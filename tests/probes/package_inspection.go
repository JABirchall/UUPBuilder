package probes

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"uupbuilder/internal/model"
)

func inspectPackage(ctx context.Context, r io.Reader) (PackageIdentity, error) {
	var identity PackageIdentity
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, r}, (4<<20)+1))
	if err != nil {
		return identity, err
	}
	if len(data) > 4<<20 {
		return identity, errors.New("package XML exceeds 4 MiB")
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	depth, roots, identities, tokens := 0, 0, 0, 0
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
			return identity, errors.New("package XML token bound exceeded")
		}
		switch t := token.(type) {
		case xml.Directive:
			return identity, errors.New("package XML directives forbidden")
		case xml.ProcInst:
			if t.Target != "xml" || roots != 0 {
				return identity, errors.New("package XML processing instructions forbidden")
			}
		case xml.StartElement:
			depth++
			if depth > 128 {
				return identity, errors.New("package XML depth bound exceeded")
			}
			seen := map[xml.Name]bool{}
			attrs := map[string]string{}
			for _, a := range t.Attr {
				if seen[a.Name] {
					return identity, errors.New("duplicate package XML attribute")
				}
				seen[a.Name] = true
				if a.Name.Space == "" {
					attrs[a.Name.Local] = a.Value
				}
			}
			if depth == 1 {
				roots++
				if roots != 1 || t.Name.Space != "urn:schemas-microsoft-com:asm.v3" || t.Name.Local != "assembly" {
					return identity, errors.New("one CBS assembly root required")
				}
			}
			if depth == 2 && t.Name.Local == "assemblyIdentity" {
				identities++
				if identities != 1 || t.Name.Space != "urn:schemas-microsoft-com:asm.v3" {
					return identity, errors.New("one direct CBS assembly identity required")
				}
				identity = PackageIdentity{attrs["name"], attrs["version"], model.Architecture(attrs["processorArchitecture"]), attrs["publicKeyToken"], attrs["language"]}
				for _, value := range []string{identity.Name, identity.Version, string(identity.Architecture), identity.PublicKeyToken, identity.Language} {
					if err := textRequired("package identity", value); err != nil {
						return identity, err
					}
				}
				if err := identity.Architecture.Validate(); err != nil {
					return identity, err
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return identity, errors.New("text outside package XML root")
			}
		}
	}
	if depth != 0 || roots != 1 || identities != 1 {
		return identity, errors.New("package XML identity incomplete")
	}
	return identity, nil
}
