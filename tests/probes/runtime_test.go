package probes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"uupbuilder/internal/model"
)

const syntheticXML = `<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" BuildArch="arm64" Type="Baseless" BuildID="b5347a24-b65f-7c51-ac95-8bdd36d866a1" OSVersion="10.0.22000.1"><Packages /></CompDB>`
const syntheticXMLHash = "df2a32c069b54f0b05a9df821d0c659b885502f8bbe73c7902a24653206e13a2"

type syntheticWorkspace struct {
	*os.Root
	path string
}

func (w *syntheticWorkspace) Path() string               { return w.path }
func (w *syntheticWorkspace) MkdirAll(name string) error { return w.Root.MkdirAll(name, 0700) }

// Synthetic ports exercise actual rooted file custody, recipe construction,
// report persistence and inspection. They are not CAB decoding/provider proof.
func observationFixture(t *testing.T) (Case, RuntimeConfig, runtimePorts, *int) {
	t.Helper()
	fixtures, parent, system := t.TempDir(), t.TempDir(), t.TempDir()
	for _, file := range []string{"fixture.cab", "expand.exe", "certutil.exe", "cabinet.dll"} {
		root := system
		if file == "fixture.cab" {
			root = fixtures
		}
		data := []byte("abc")
		if file == "fixture.cab" {
			data = syntheticCAB()
			binary.LittleEndian.PutUint32(data[44:], uint32(len(syntheticXML)))
			data[len(data)-3] = byte(len(syntheticXML))
			data[len(data)-2] = byte(len(syntheticXML) >> 8)
		}
		if err := os.WriteFile(filepath.Join(root, file), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := Case{ID: "synthetic-compdb-observation", Gate: "S", Host: HostRequirement{"windows", 10240, "amd64", "amd64"}, Target: "arm64", SourceFamily: "compdb-metadata-observation", Source: model.SourceIdentity{UpdateID: "synthetic_rev.1", BuildLabel: "synthetic", Architecture: "arm64", Language: "en-us"}, RevisionProvenance: "synthetic fixture", Inputs: []Artifact{unitArtifact("cab", "metadata")}, Operations: []Operation{Extract}, Pending: []Blocker{{"real-payload-proof-missing", "Metadata observation does not prove an image/source family."}}}
	for _, component := range []struct{ id, role string }{{"expand", "executable"}, {"certutil", "executable"}, {"cabinet", "dll"}} {
		c.Components = append(c.Components, Component{Artifact: unitArtifact(component.id, component.role), NativeArchitecture: "amd64"})
	}
	c.Expected = []Expectation{{ID: "xml", Operation: Extract, OutputID: "xml-output", SHA256: syntheticXMLHash, Provenance: "hand-fixed synthetic XML digest", Assertions: []string{"files-and-metadata-inspected"}}}
	sourceBytes, err := os.ReadFile(filepath.Join(fixtures, "fixture.cab"))
	if err != nil {
		t.Fatal(err)
	}
	sourceHash := sha256.Sum256(sourceBytes)
	c.Inputs[0].Size = int64(len(sourceBytes))
	c.Inputs[0].Digest.Value = hex.EncodeToString(sourceHash[:])
	cfg := RuntimeConfig{CaseDigest: c.Digest(), FixtureRoot: fixtures, WorkspaceParent: parent, Inputs: []FileBinding{{"cab", "fixture.cab"}}, Components: []FileBinding{{"expand", "expand.exe"}, {"certutil", "certutil.exe"}, {"cabinet", "cabinet.dll"}}, Recipe: ExpandCompDBCABV1, Extraction: CompDBExtraction{InputID: "cab", ExpectationID: "xml", ExpandID: "expand", CertutilID: "certutil", Member: "member.xml", Identity: CompDBIdentity{"arm64", "Baseless", "b5347a24-b65f-7c51-ac95-8bdd36d866a1", "10.0.22000.1"}}}
	calls := new(int)
	ports := runtimePorts{kind: "synthetic-runtime", observe: func() (ObservedHost, error) {
		return ObservedHost{OS: "windows", Host: model.Host{WindowsBuild: 19045, NativeArchitecture: "amd64", ProcessArchitecture: "amd64"}}, nil
	}, createWorkspace: func(parent, id string) (proofWorkspace, error) {
		p, err := os.MkdirTemp(parent, "synthetic-")
		if err != nil {
			return nil, err
		}
		r, err := os.OpenRoot(p)
		return &syntheticWorkspace{r, p}, err
	}, fileSystem: func(string) (model.FileSystemCapabilities, error) {
		return model.FileSystemCapabilities{Name: "NTFS", Local: true}, nil
	}, openComponent: func(name string, arch model.Architecture) (*os.File, string, error) {
		p := filepath.Join(system, name)
		f, err := os.Open(p)
		return f, p, err
	}, run: func(ctx context.Context, w proofWorkspace, req directRequest, emit model.Emit) (processResult, error) {
		*calls++
		switch filepath.Base(req.Executable) {
		case "expand.exe":
			want := []string{filepath.FromSlash("inputs/0.cab"), "-F:member.xml", "outputs"}
			if !reflect.DeepEqual(req.Arguments, want) {
				return processResult{}, errors.New("wrong fixed expand argv")
			}
			f, err := w.OpenFile("outputs/0.cab", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return processResult{}, err
			}
			_, err = f.WriteString(syntheticXML)
			err = errors.Join(err, f.Close())
			return processResult{PID: 101, Stdout: "synthetic extracted XML"}, err
		case "certutil.exe":
			want := []string{"-hashfile", filepath.Join(w.Path(), "outputs", "0.cab"), "SHA256"}
			if !reflect.DeepEqual(req.Arguments, want) {
				return processResult{}, errors.New("wrong fixed certutil argv")
			}
			return processResult{PID: 102, Stdout: "synthetic hash output\r\n" + syntheticXMLHash + "\r\n"}, nil
		}
		return processResult{}, errors.New("unknown synthetic executable")
	}}
	return c, cfg, ports, calls
}

func TestRuntimeRetainsObservedBytesAndHonestPartialEvidence(t *testing.T) {
	c, cfg, ports, calls := observationFixture(t)
	e, err := executeRuntime(context.Background(), c, nil, cfg, ports)
	if err == nil || e.Status != Unverified || e.ExecutionKind != "synthetic-runtime" || *calls != 2 || len(e.Invocations) != 2 || len(e.Outputs) != 1 || len(e.Verifications) != 1 {
		t.Fatalf("component observation missing: evidence=%+v calls=%d error=%v", e, *calls, err)
	}
	if len(e.Invocations[0].Algorithms) != 0 || contains(e.Verifications[0].Assertions, "files-and-metadata-inspected") {
		t.Fatal("metadata-only inspection manufactured full extraction/algorithm evidence")
	}
	if e.Verifications[0].ObservedTarget != "arm64" || e.Verifications[0].SHA256 != syntheticXMLHash {
		t.Fatalf("actual XML inspection not bound: %+v", e.Verifications)
	}
	if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
		t.Fatal("synthetic metadata observation opened gate")
	}
	if e.Host.Report.Digest.Value == "" || e.Invocations[0].Log.Size == 0 || e.Verifications[0].Report.Size == 0 {
		t.Fatal("real retained reports/logs missing")
	}
	// The host-report provenance locates the retained workspace without making
	// handwritten JSON an attestation. Persistence errors must never be hidden.
	if !strings.Contains(e.Host.Report.Provenance, "host.json") {
		t.Fatal("host report has no retained location")
	}
}

func TestRuntimeRejectsUnboundOrUnsafeConfigurationBeforeLaunch(t *testing.T) {
	for _, test := range []string{"case digest", "recipe", "traversal", "wildcard member", "unknown input", "unknown component", "target", "missing binding"} {
		t.Run(test, func(t *testing.T) {
			c, cfg, p, calls := observationFixture(t)
			switch test {
			case "case digest":
				cfg.CaseDigest = unitHash
			case "recipe":
				cfg.Recipe = "arbitrary-shell"
			case "traversal":
				cfg.Inputs[0].Path = "../fixture.cab"
			case "wildcard member":
				cfg.Extraction.Member = "*.xml"
			case "unknown input":
				cfg.Extraction.InputID = "absent"
			case "unknown component":
				cfg.Components[0].Path = "cmd.exe"
			case "target":
				cfg.Extraction.Identity.Architecture = "x86"
			case "missing binding":
				cfg.Components = cfg.Components[:2]
			}
			e, err := executeRuntime(context.Background(), c, nil, cfg, p)
			if err == nil || e.Status != Unverified || *calls != 0 {
				t.Fatalf("unsafe configuration executed: %+v calls=%d err=%v", e, *calls, err)
			}
		})
	}
}

func TestRuntimeZeroExitDoesNotReplaceOutputInspection(t *testing.T) {
	for _, test := range []string{"no output", "wrong output", "false independent hash", "nonzero exit", "cancelled"} {
		t.Run(test, func(t *testing.T) {
			c, cfg, p, _ := observationFixture(t)
			original := p.run
			p.run = func(ctx context.Context, w proofWorkspace, req directRequest, emit model.Emit) (processResult, error) {
				if test == "no output" {
					return processResult{PID: 101}, nil
				}
				r, err := original(ctx, w, req, emit)
				if filepath.Base(req.Executable) == "expand.exe" {
					switch test {
					case "wrong output":
						f, e := w.OpenFile("outputs/0.cab", os.O_WRONLY|os.O_TRUNC, 0600)
						if e != nil {
							return r, e
						}
						_, e = f.WriteString("abc")
						return r, errors.Join(e, f.Close())
					case "nonzero exit":
						r.Exit = 7
						return r, errors.New("synthetic exit 7")
					case "cancelled":
						r.Cancelled = true
						return r, context.Canceled
					}
				}
				if test == "false independent hash" && filepath.Base(req.Executable) == "certutil.exe" {
					r.Stdout = unitHash
				}
				return r, err
			}
			e, err := executeRuntime(context.Background(), c, nil, cfg, p)
			if err == nil || e.Status == Passed || len(e.Verifications) != 0 {
				t.Fatalf("failed content accepted: %+v / %v", e, err)
			}
			if test == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
		})
	}
}

func TestRuntimeContextSnapshotDoesNotShareBindings(t *testing.T) {
	_, cfg, _, _ := observationFixture(t)
	ctx := WithRuntime(context.Background(), cfg)
	cfg.Inputs[0].Path = "changed"
	got := ctx.Value(runtimeKey{}).(RuntimeConfig)
	if got.Inputs[0].Path != "fixture.cab" {
		t.Fatal("request recipe mutated after binding")
	}
}

func TestRuntimePublicEvidenceOmitsPrivateLocationsOnFailure(t *testing.T) {
	c, cfg, p, _ := observationFixture(t)
	cfg.FixtureRoot = filepath.Join(cfg.FixtureRoot, "private-missing-fixture-root")
	e, err := executeRuntime(context.Background(), c, nil, cfg, p)
	if err == nil || e.RetainedWorkspace == "" {
		t.Fatalf("missing fixture failure was not retained: %+v %v", e, err)
	}
	public, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{cfg.FixtureRoot, cfg.WorkspaceParent, e.RetainedWorkspace, "private-missing-fixture-root"} {
		if strings.Contains(string(public), secret) || strings.Contains(string(public), strings.ReplaceAll(secret, `\`, `\\`)) {
			t.Fatalf("public evidence leaked private location %q: %s", secret, public)
		}
	}
	if _, err := os.Stat(filepath.Join(e.RetainedWorkspace, "run.json")); err != nil {
		t.Fatalf("private failure record missing: %v", err)
	}
}

func TestRuntimeAppliesFiniteProbeDeadline(t *testing.T) {
	c, cfg, p, _ := observationFixture(t)
	original := p.run
	p.run = func(ctx context.Context, w proofWorkspace, req directRequest, emit model.Emit) (processResult, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
			return processResult{}, errors.New("finite 30-second probe deadline missing")
		}
		return original(ctx, w, req, emit)
	}
	e, err := executeRuntime(context.Background(), c, nil, cfg, p)
	if len(e.Verifications) != 1 {
		t.Fatalf("probe deadline missing: %+v %v", e, err)
	}
}

func TestRuntimeFreezesCaseBeforeExternalCallbacks(t *testing.T) {
	c, cfg, p, _ := observationFixture(t)
	original := p.observe
	p.observe = func() (ObservedHost, error) {
		c.Inputs[0].Digest.Value = unitBeforeHash
		c.Components[0].Artifact.Size = 99
		return original()
	}
	e, err := executeRuntime(context.Background(), c, nil, cfg, p)
	if len(e.Verifications) != 1 || e.CaseDigest != cfg.CaseDigest {
		t.Fatalf("caller mutation changed frozen run: %+v %v", e, err)
	}
}

func TestRuntimeKeepsPrivateOwnerInPrivateRecordOnly(t *testing.T) {
	c, cfg, p, _ := observationFixture(t)
	const token = "private-owner-token-regression"
	p.privateWorkspace = func(w proofWorkspace) any {
		return struct {
			Path  string `json:"path"`
			Token string `json:"token"`
		}{w.Path(), token}
	}
	e, err := executeRuntime(context.Background(), c, nil, cfg, p)
	if len(e.Verifications) != 1 {
		t.Fatalf("observation incomplete: %v", err)
	}
	for _, encode := range []func(any) ([]byte, error){json.Marshal, toml.Marshal} {
		b, err := encode(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{token, e.RetainedWorkspace, cfg.FixtureRoot, cfg.WorkspaceParent} {
			if bytes.Contains(b, []byte(secret)) || bytes.Contains(b, []byte(strings.ReplaceAll(secret, `\`, `\\`))) {
				t.Fatal("public evidence serialized private owner/location")
			}
		}
	}
	private, err := os.ReadFile(filepath.Join(e.RetainedWorkspace, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(private, []byte(token)) || !bytes.Contains(private, []byte(`"custody"`)) || !bytes.Contains(private, []byte(`"runtime"`)) {
		t.Fatal("private retained record lost ownership/custody/frozen recipe")
	}
	other := cfg
	other.FixtureRoot = t.TempDir()
	other.WorkspaceParent = t.TempDir()
	if cfg.digest() != other.digest() {
		t.Fatal("root location incorrectly changed identity-only runtime digest")
	}
	other.Inputs = append([]FileBinding(nil), cfg.Inputs...)
	other.Inputs[0].Path = "different-fixture.cab"
	if cfg.digest() == other.digest() {
		t.Fatal("runtime digest ignored relative fixture binding")
	}
}
