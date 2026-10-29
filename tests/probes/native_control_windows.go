package probes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	platform "uupbuilder/internal/platform/windows"
)

// This private diagnostic has no Case/Evidence/RuntimeConfig producer. Its
// authenticated MCT media-input ESD has no UUP update identity.
const controlProfile = "desktop-index9-input0809-v1"
const controlSourceSHA = "0c8cc284d29d6b9bee19daa3fbb7bafd7536d98069c2cd0cc7055e2703eda7e9"
const controlSourceSHA1 = "e35f49be74010d22e1bf9d2f200e48f3f7fd0a66"
const controlToolSHA = "6a2bc5111b7ea9c4c6fdca0db462187b8b9b1ef009bd2d28a2a0124e3d31b95d"

type controlVersionFields struct {
	NumericFileVersion    string `json:"numeric_file_version"`
	DisplayFileVersion    string `json:"display_file_version"`
	NumericProductVersion string `json:"numeric_product_version"`
	DisplayProductVersion string `json:"display_product_version"`
}
type controlPin struct {
	Size     int64                 `json:"size"`
	SHA256   string                `json:"sha256"`
	SHA1     string                `json:"sha1,omitempty"`
	Versions controlVersionFields  `json:"versions"`
	Machine  uint16                `json:"machine,omitempty"`
	Identity platform.FileIdentity `json:"file_identity"`
	Links    uint32                `json:"links"`
}

func controlSameBytes(a, b controlPin) bool {
	return a.Size == b.Size && a.SHA256 == b.SHA256 && a.SHA256 != ""
}

type controlFacts struct {
	Build    uint32     `json:"build"`
	Native   string     `json:"native"`
	Process  string     `json:"process"`
	SID      string     `json:"sid"`
	Source   controlPin `json:"source"`
	Tool     controlPin `json:"tool"`
	Runner   controlPin `json:"runner"`
	Elevated bool       `json:"elevated"`
	Free     uint64     `json:"free"`
}

// Capabilities are private, never included in checkpoint outputs or public
// reports. The approving invocation separately pins the complete request hash.
type controlRequest struct {
	Version  int                        `json:"version"`
	Profile  string                     `json:"profile"`
	Plan     string                     `json:"plan"`
	Source   string                     `json:"source"`
	Tool     string                     `json:"tool"`
	Runner   string                     `json:"runner"`
	Facts    controlFacts               `json:"facts"`
	Bundle   platform.WorkspaceIdentity `json:"bundle"`
	Store    platform.WorkspaceIdentity `json:"store"`
	Provider platform.WorkspaceIdentity `json:"provider"`
	Apply    platform.WorkspaceIdentity `json:"apply"`
	ScopeIDs [4]platform.FileIdentity   `json:"scope_ids"`
}

func controlHash(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func decodeControl(b []byte, sha string) (controlRequest, error) {
	var r controlRequest
	if len(b) > 32<<10 || len(sha) != 64 || controlHash(b) != sha {
		return r, errors.New("unsealed control request bytes")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	if d.Decode(new(any)) != io.EOF {
		return r, errors.New("trailing request data")
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(canonical, b) {
		return r, errors.New("noncanonical or duplicate control request fields")
	}
	return r, nil
}
func controlPath(p string) string      { return filepath.Clean(strings.TrimPrefix(p, `\\?\`)) }
func sameControlPath(a, b string) bool { return strings.EqualFold(controlPath(a), controlPath(b)) }
func validateControl(r controlRequest, a controlFacts, elevated bool) error {
	if r.Version != 1 || r.Profile != controlProfile || !filepath.IsAbs(r.Plan) || filepath.Base(r.Plan) != "2026-10-28-uup-builder-remaining-work-plan" {
		return errors.New("wrong compiled control profile or plan namespace")
	}
	if r.Facts.Source.Size != 4164077935 || r.Facts.Source.SHA256 != controlSourceSHA || r.Facts.Source.SHA1 != controlSourceSHA1 || r.Facts.Tool.Size != 289136 || r.Facts.Tool.SHA256 != controlToolSHA || r.Facts.Tool.Machine != 0x8664 || r.Facts.Tool.Versions != (controlVersionFields{NumericFileVersion: "10.0.19041.3636", DisplayFileVersion: "10.0.19041.1 (WinBuild.160101.0800)", NumericProductVersion: "10.0.19041.3636", DisplayProductVersion: "10.0.19041.1"}) {
		return errors.New("control source/tool differs from frozen recipe")
	}
	if r.Facts.Runner.Machine != 0x8664 || r.Facts.Runner.Size <= 0 || len(r.Facts.Runner.SHA256) != 64 {
		return errors.New("invalid compiled native control runner identity")
	}
	if a.Build != 19045 || a.Native != "amd64" || a.Process != "amd64" || a.SID == "" || a.Build != r.Facts.Build || a.Native != r.Facts.Native || a.Process != r.Facts.Process || a.SID != r.Facts.SID || a.Source != r.Facts.Source || a.Tool != r.Facts.Tool || a.Runner != r.Facts.Runner {
		return errors.New("measured source/tool/runner/host/owner differs from sealed request")
	}
	if elevated && !a.Elevated {
		return errors.New("same-user elevated token required; this entry never elevates itself")
	}
	if a.Free < 100<<30 {
		return errors.New("100 GiB free-space allowance required before image work")
	}
	seen := map[string]bool{}
	for i, id := range []platform.WorkspaceIdentity{r.Bundle, r.Store, r.Provider, r.Apply} {
		p := controlPath(id.Path)
		token, err := hex.DecodeString(id.Token)
		if err != nil || len(token) != 16 || id.Token != strings.ToLower(id.Token) || id.JobID != "desktop-control" || !sameControlPath(filepath.Dir(p), filepath.Join(r.Plan, "r3a2b")) || filepath.Base(p) != "uupbuilder-"+id.Token || seen[strings.ToLower(p)] || r.ScopeIDs[i].FileIndex == 0 {
			return errors.New("foreign or unsafe role workspace")
		}
		seen[strings.ToLower(p)] = true
	}
	if !sameControlPath(r.Source, filepath.Join(r.Plan, "native-control", "source", "desktop-control.esd")) || !sameControlPath(r.Runner, filepath.Join(r.Bundle.Path, "runner.exe")) || !strings.EqualFold(filepath.Base(r.Tool), "dism.exe") || !strings.EqualFold(filepath.Base(filepath.Dir(r.Tool)), "System32") {
		return errors.New("foreign control source/tool/runner path")
	}
	return nil
}

type controlPaths struct{ Source, Before, Working, After, Mount, Apply, Provider string }

var controlOperations = []string{"i0", "s0", "e0", "b0", "m0", "d0", "q0", "x0", "q1", "u0", "e1", "a0", "p0", "i1"}

func controlArguments(op string, p controlPaths) ([]string, error) {
	a := []string{"/English", "/NoRestart"}
	switch op {
	case "i0", "i1", "ri":
		a = append(a, "/Get-MountedImageInfo")
	case "s0":
		a = append(a, "/Get-ImageInfo", "/ImageFile:"+p.Source, "/Index:9")
	case "b0":
		a = append(a, "/Get-ImageInfo", "/ImageFile:"+p.Before, "/Index:1")
	case "a0":
		a = append(a, "/Get-ImageInfo", "/ImageFile:"+p.After, "/Index:1")
	case "e0":
		a = append(a, "/Export-Image", "/SourceImageFile:"+p.Source, "/SourceIndex:9", "/DestinationImageFile:"+p.Before, "/Compress:max", "/CheckIntegrity")
	case "e1":
		a = append(a, "/Export-Image", "/SourceImageFile:"+p.Working, "/SourceIndex:1", "/DestinationImageFile:"+p.After, "/Compress:max", "/CheckIntegrity")
	case "m0":
		a = append(a, "/Mount-Image", "/ImageFile:"+p.Working, "/Index:1", "/MountDir:"+p.Mount, "/CheckIntegrity")
	case "d0":
		a = append(a, "/Image:"+p.Mount, "/Get-CurrentEdition")
	case "q0", "q1":
		a = append(a, "/Image:"+p.Mount, "/Get-Intl")
	case "x0":
		a = append(a, "/Image:"+p.Mount, "/Set-InputLocale:0809:00000809")
	case "u0":
		a = append(a, "/Unmount-Image", "/MountDir:"+p.Mount, "/Commit", "/CheckIntegrity")
	case "r0":
		a = append(a, "/Unmount-Image", "/MountDir:"+p.Mount, "/Discard")
	case "p0":
		a = append(a, "/Apply-Image", "/ImageFile:"+p.After, "/Index:1", "/ApplyDir:"+p.Apply, "/CheckIntegrity", "/Verify")
	default:
		return nil, errors.New("operation outside fixed control graph")
	}
	return append(a, "/ScratchDir:"+filepath.Join(p.Provider, "tmp"), "/LogPath:"+filepath.Join(p.Provider, "logs", op+".log")), nil
}
func sequenceControl(ctx context.Context, step func(context.Context, string) error) error {
	for _, op := range controlOperations {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := step(ctx, op); err != nil {
			return fmt.Errorf("control %s: %w", op, err)
		}
	}
	return nil
}

type controlPlannedCommand struct {
	Operation string
	Arguments []string
}
type controlOperationProposal struct {
	StageTokenWidth, MaxNativePath int
	StagePlaceholder               string
	FutureStageExists              bool
	Commands                       []controlPlannedCommand
	Recovery                       []string
}

func controlPathBound(p controlPaths) (int, error) {
	max := 0
	for _, op := range append(append([]string{}, controlOperations...), "ri", "r0") {
		args, e := controlArguments(op, p)
		if e != nil {
			return 0, e
		}
		for _, a := range args {
			if strings.ContainsAny(a, "\x00\r\n") {
				return 0, errors.New("unsafe native argument")
			}
			_, path, has := strings.Cut(a, ":")
			if has && filepath.IsAbs(path) {
				if len(path) > max {
					max = len(path)
				}
				if len(path) >= 260 {
					return 0, fmt.Errorf("native argument path exceeds reviewed bound: %s", path)
				}
			}
		}
	}
	return max, nil
}
func controlProposal(r controlRequest) (proposal controlOperationProposal, err error) {
	// Exactly 32 Xs are a length-only placeholder, never an allocated stage
	// token or a launchable authorization. J1 creates the real token at run.
	token := strings.Repeat("X", 32)
	scratch := controlPath(filepath.Join(r.Store.Path, "scratch", token))
	p := controlPaths{Source: controlPath(r.Source), Before: filepath.Join(scratch, "before.wim"), Working: filepath.Join(scratch, "working.wim"), After: filepath.Join(scratch, "after.wim"), Mount: filepath.Join(scratch, "mount"), Apply: controlPath(filepath.Join(r.Apply.Path, "image")), Provider: controlPath(r.Provider.Path)}
	proposal.StageTokenWidth = 32
	proposal.StagePlaceholder = token
	proposal.MaxNativePath, err = controlPathBound(p)
	if err != nil {
		return proposal, err
	}
	for _, op := range controlOperations {
		args, e := controlArguments(op, p)
		if e != nil {
			return proposal, e
		}
		proposal.Commands = append(proposal.Commands, controlPlannedCommand{op, args})
	}
	proposal.Recovery, err = controlArguments("r0", p)
	return proposal, err
}

type controlMount struct {
	Path, Image       string
	Index             uint32
	ReadWrite, Status string
}

func normalizeControlOutput(s string) (string, error) {
	b := []byte(s)
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		b = b[2:]
		if len(b)%2 != 0 {
			return "", errors.New("odd native UTF16 output")
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
		}
		for i := 0; i < len(u); i++ {
			if u[i] >= 0xd800 && u[i] <= 0xdbff {
				if i+1 == len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
					return "", errors.New("malformed native UTF16 output")
				}
				i++
			} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
				return "", errors.New("malformed native UTF16 output")
			}
		}
		s = string(utf16.Decode(u))
	} else {
		s = strings.TrimPrefix(s, "\ufeff")
	}
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return "", errors.New("unsupported native stdout encoding")
	}
	return s, nil
}

func controlFields(s string) (map[string]string, error) {
	m := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		k, v, ok := strings.Cut(line, " : ")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || m[k] != "" {
			return nil, errors.New("ambiguous native query fields")
		}
		m[k] = v
	}
	return m, nil
}
func parseControlMounts(s string) ([]controlMount, error) {
	var err error
	s, err = normalizeControlOutput(s)
	if err != nil {
		return nil, err
	}
	if strings.Count(s, "Mounted images:") != 1 || strings.Count(s, "The operation completed successfully.") != 1 {
		return nil, errors.New("incomplete native mounted-image inventory")
	}
	if strings.Contains(s, "No mounted images.") {
		if strings.Contains(s, "Mount Dir :") {
			return nil, errors.New("contradictory mount inventory")
		}
		return []controlMount{}, nil
	}
	var out []controlMount
	seen := map[string]bool{}
	for _, block := range strings.Split(s, "Mount Dir :")[1:] {
		f, err := controlFields("Mount Dir :" + block)
		if err != nil {
			return nil, err
		}
		index, err := strconv.ParseUint(f["Image Index"], 10, 32)
		if err != nil || index == 0 || !filepath.IsAbs(f["Mount Dir"]) || !filepath.IsAbs(f["Image File"]) || f["Status"] == "" || f["Mounted Read/Write"] == "" {
			return nil, errors.New("malformed mount inventory entry")
		}
		key := strings.ToLower(controlPath(f["Mount Dir"]))
		if seen[key] {
			return nil, errors.New("duplicate mount inventory path")
		}
		seen[key] = true
		out = append(out, controlMount{f["Mount Dir"], f["Image File"], uint32(index), f["Mounted Read/Write"], f["Status"]})
	}
	if len(out) == 0 {
		return nil, errors.New("unrecognized empty inventory")
	}
	return out, nil
}
func controlOwnedMount(m []controlMount, p controlPaths) error {
	found := false
	for _, v := range m {
		if sameControlPath(v.Path, p.Mount) {
			if found || !sameControlPath(v.Image, p.Working) || v.Index != 1 || v.ReadWrite != "Yes" || v.Status != "Ok" {
				return errors.New("owned native mount metadata conflicts")
			}
			found = true
		}
	}
	if !found {
		return errors.New("exact owned registered mount not found")
	}
	return nil
}
func controlUnrelated(a, b []controlMount, owned string) error {
	filter := func(m []controlMount) map[string]controlMount {
		out := map[string]controlMount{}
		for _, v := range m {
			if !sameControlPath(v.Path, owned) {
				v.Path = strings.ToLower(controlPath(v.Path))
				v.Image = strings.ToLower(controlPath(v.Image))
				out[v.Path] = v
			}
		}
		return out
	}
	if !reflect.DeepEqual(filter(a), filter(b)) {
		return errors.New("unrelated mounted-image inventory changed")
	}
	return nil
}
func controlScopesUnmounted(mounts []controlMount, scopes []string) error {
	for _, m := range mounts {
		a := strings.ToLower(controlPath(m.Path))
		for _, scope := range scopes {
			b := strings.ToLower(controlPath(scope))
			prefix := func(s string) string { return strings.TrimRight(s, `\`) + `\` }
			if a == b || strings.HasPrefix(a, prefix(b)) || strings.HasPrefix(b, prefix(a)) {
				return errors.New("prepared role scope overlaps an actual mounted image")
			}
		}
	}
	return nil
}
func assertControlImageInfo(s string, index int) error {
	f, err := controlFields(s)
	if err != nil {
		return err
	}
	for k, want := range map[string]string{"Index": strconv.Itoa(index), "Name": "Windows 10 Pro", "Architecture": "x64", "Version": "10.0.19041", "ServicePack Build": "3803", "Edition": "Professional", "Installation": "Client"} {
		if f[k] != want {
			return fmt.Errorf("native source/image field %s = %q, want %q", k, f[k], want)
		}
	}
	if !strings.Contains(s, "en-US (Default)") {
		return errors.New("native image default language differs")
	}
	return nil
}
func assertControlIntl(s string, after bool) error {
	f, err := controlFields(s)
	if err != nil {
		return err
	}
	keyboard := "0409:00000409"
	if after {
		keyboard = "0809:00000809"
	}
	for k, w := range map[string]string{"Default system UI language": "en-US", "System locale": "en-US", "User locale for default user": "en-US", "Active keyboard(s)": keyboard} {
		if f[k] != w {
			return fmt.Errorf("native international field %s = %q, want %q", k, f[k], w)
		}
	}
	return nil
}
