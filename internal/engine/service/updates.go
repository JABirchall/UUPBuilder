package service

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func verifyUpdates(ctx context.Context, req ServiceRequest) (map[string]string, error) {
	paths := map[string]string{}
	for _, update := range req.Plan.Updates {
		var path string
		for _, input := range req.Payloads {
			if input.Resource == update.Resource {
				if path != "" {
					return nil, fmt.Errorf("ambiguous update input %s", update.ID)
				}
				path = input.Path
			}
		}
		if path == "" {
			return nil, fmt.Errorf("missing verified update input %s", update.ID)
		}
		if err := verifyUpdateFile(ctx, update.Resource.Payload, path); err != nil {
			return nil, fmt.Errorf("update %s: %w", update.ID, err)
		}
		paths[update.ID] = path
	}
	return paths, nil
}

func verifyUpdateFile(ctx context.Context, id model.PayloadIdentity, path string) error {
	var h hash.Hash
	switch id.Digest.Algorithm {
	case model.DigestMD5:
		h = md5.New()
	case model.DigestSHA1:
		h = sha1.New()
	case model.DigestSHA256:
		h = sha256.New()
	case model.DigestSHA384:
		h = sha512.New384()
	case model.DigestSHA512:
		h = sha512.New()
	default:
		return ErrVerification
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(h, &contextReader{ctx: ctx, r: io.LimitReader(f, id.Size+1)})
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != id.Size || hex.EncodeToString(h.Sum(nil)) != id.Digest.Value {
		return fmt.Errorf("%w: update bytes", ErrVerification)
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
func copyRetained(ctx context.Context, req ServiceRequest, name, path string) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := req.Transaction.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, &contextReader{ctx, src})
	if err == nil {
		err = dst.Sync()
	}
	closeErr := dst.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func verifyPackages(observed []PackageObservation, required []metadata.PackageIdentity) error {
	for _, expected := range required {
		found := false
		for _, actual := range observed {
			if samePackage(actual.Identity, expected) && (strings.EqualFold(actual.State, "Installed") || strings.EqualFold(actual.State, "Install Pending") || strings.EqualFold(actual.State, "Superseded")) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: missing required package %s %s", ErrVerification, expected.Name, expected.Version)
		}
	}
	return nil
}

func samePackage(a, b metadata.PackageIdentity) bool {
	language := func(value string) string {
		if strings.EqualFold(value, "neutral") {
			return ""
		}
		return strings.ToLower(value)
	}
	return strings.EqualFold(a.Name, b.Name) && a.Version == b.Version && strings.EqualFold(a.PublicKeyToken, b.PublicKeyToken) && strings.EqualFold(string(a.Architecture), string(b.Architecture)) && language(a.Language) == language(b.Language)
}

// Checkpoints are verified exactly immediately after application. Once their
// descendants are installed, CBS cleanup can remove superseded SSU/LCU entries.
// Only a newer, active, exact source-planned package in a descendant update may
// satisfy that historical requirement; the newest targets remain mandatory.
func verifyIntegratedPackages(observed []PackageObservation, updates []rules.UpdatePlan, edition string) error {
	applicable := map[string]rules.UpdatePlan{}
	for _, update := range updates {
		if update.Integrate && rules.Applies(update, edition) {
			applicable[update.ID] = update
		}
	}
	for _, update := range updates {
		if _, ok := applicable[update.ID]; !ok {
			continue
		}
		for _, expected := range update.Packages {
			if verifyPackages(observed, []metadata.PackageIdentity{expected}) == nil {
				continue
			}
			replaced := false
			for _, candidate := range updates {
				if _, ok := applicable[candidate.ID]; !ok || !updateDescendsFrom(candidate.ID, update.ID, applicable, map[string]bool{}) {
					continue
				}
				for _, replacement := range candidate.Packages {
					if !newerCumulativePackage(replacement, expected) {
						continue
					}
					for _, actual := range observed {
						if samePackage(actual.Identity, replacement) && (strings.EqualFold(actual.State, "Installed") || strings.EqualFold(actual.State, "Install Pending")) {
							replaced = true
						}
					}
				}
			}
			if !replaced {
				return verifyPackages(observed, []metadata.PackageIdentity{expected})
			}
		}
	}
	return nil
}

func updateDescendsFrom(id, predecessor string, updates map[string]rules.UpdatePlan, visited map[string]bool) bool {
	if visited[id] {
		return false
	}
	visited[id] = true
	for _, parent := range updates[id].Predecessors {
		if parent == predecessor || updateDescendsFrom(parent, predecessor, updates, visited) {
			return true
		}
	}
	return false
}

func newerCumulativePackage(candidate, expected metadata.PackageIdentity) bool {
	family := func(name string) string {
		name = strings.ToLower(name)
		if name == "package_for_rollupfix" {
			return name
		}
		const prefix = "package_for_servicingstack_"
		if strings.HasPrefix(name, prefix) {
			if _, err := strconv.ParseUint(strings.TrimPrefix(name, prefix), 10, 32); err == nil {
				return prefix
			}
		}
		return ""
	}
	if family(expected.Name) == "" || family(candidate.Name) != family(expected.Name) {
		return false
	}
	left, right := strings.Split(candidate.Version, "."), strings.Split(expected.Version, ".")
	if len(left) != 4 || len(right) != 4 {
		return false
	}
	comparison := 0
	for i := range left {
		a, errA := strconv.ParseUint(left[i], 10, 32)
		b, errB := strconv.ParseUint(right[i], 10, 32)
		if errA != nil || errB != nil || i == 0 && a != b {
			return false
		}
		if comparison == 0 && a != b {
			if a > b {
				comparison = 1
			} else {
				comparison = -1
			}
		}
	}
	identity := candidate
	identity.Name, identity.Version = expected.Name, expected.Version
	return comparison > 0 && samePackage(identity, expected)
}
