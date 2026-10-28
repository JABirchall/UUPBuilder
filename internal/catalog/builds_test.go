package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"uupbuilder/internal/model"
)

const sourceID = "db8ec987-d136-4421-afb8-2ef109396b00"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func serveJSON(t *testing.T, data []byte) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestBuildsAcceptArrayAndSparseObject(t *testing.T) {
	for _, name := range []string{"builds-array.json", "builds-sparse.json"} {
		t.Run(name, func(t *testing.T) {
			s := serveJSON(t, fixture(t, name))
			builds, err := New(s.Client(), s.URL).Search(context.Background(), "all")
			if err != nil {
				t.Fatal(err)
			}
			if len(builds) != 3 {
				t.Fatalf("want three records, got %+v", builds)
			}
		})
	}
}

func TestSparseKeysNeverBecomeIdentity(t *testing.T) {
	s := serveJSON(t, fixture(t, "builds-sparse.json"))
	builds, err := New(s.Client(), s.URL).Search(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{sourceID, "a1b78728-530f-443f-b672-d742e7c14bcb", "5486793c-ef16-4f21-b397-f0321a833424_rev.2"}
	var got []string
	for _, b := range builds {
		got = append(got, b.UpdateID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("record identities: got %v want %v", got, want)
	}
	if builds[0].CreatedAt.Unix() != 1630393455 || builds[0].Architecture != "arm64" {
		t.Fatalf("lost build properties: %+v", builds[0])
	}
}

func TestBuildsPreserveExplicitUnknownCreationTime(t *testing.T) {
	s := serveJSON(t, fixture(t, "builds-null-created.json"))
	builds, err := New(s.Client(), s.URL).Search(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Build{
		{UpdateID: "e8706433-04f4-4a00-b58f-df8ed1bab586", Title: "Windows 11, version 26H1 (28000.3365)", Build: "28000.3365", Architecture: "arm64", CreatedAt: time.Unix(1793208203, 0).UTC()},
		{UpdateID: "bd8d3d91-5716-4f3d-8f00-4c30bc6f6bfa_rev.2", Title: "Feature update to Windows 10, version 1709 (16299.19)", Build: "16299.19", Architecture: "x86", CreatedAt: time.Unix(1751614394, 0).UTC()},
		{UpdateID: "f2913c3d-4ddb-43c0-a309-edb81644a540", Title: "Windows 10 Insider Preview 18343.1 (19h1_release)", Build: "18343.1", Architecture: "amd64", CreatedAt: time.Time{}},
	}
	if !reflect.DeepEqual(builds, want) {
		t.Fatalf("catalog lost records, upstream order, identity, or date precision:\ngot  %+v\nwant %+v", builds, want)
	}
}

func TestBuildsRejectMalformedOrConflictingRecordsWithUnknownDate(t *testing.T) {
	const record = `{"title":"Legacy update","build":"18343.1","arch":"future128","created":null,"uuid":"f2913c3d-4ddb-43c0-a309-edb81644a540_rev.2"}`
	for _, tt := range []struct{ name, records string }{
		{"missing-created", strings.Replace(record, `"created":null,`, "", 1)},
		{"string-created", strings.Replace(record, `"created":null`, `"created":"123"`, 1)},
		{"boolean-created", strings.Replace(record, `"created":null`, `"created":false`, 1)},
		{"fractional-created", strings.Replace(record, `"created":null`, `"created":1.5`, 1)},
		{"object-created", strings.Replace(record, `"created":null`, `"created":{}`, 1)},
		{"negative-created", strings.Replace(record, `"created":null`, `"created":-1`, 1)},
		{"invalid-uuid", strings.Replace(record, `f2913c3d-4ddb-43c0-a309-edb81644a540_rev.2`, `invalid`, 1)},
		{"empty-title", strings.Replace(record, `"Legacy update"`, `" "`, 1)},
		{"empty-build", strings.Replace(record, `"18343.1"`, `""`, 1)},
		{"invalid-architecture", strings.Replace(record, `"future128"`, `"arm 64"`, 1)},
		{"duplicate-identity", record + "," + record},
		{"conflicting-identity", record + "," + strings.Replace(record, `"future128"`, `"arm64"`, 1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if builds, err := parseBuilds([]byte(`{"response":{"builds":[` + tt.records + `]}}`)); err == nil || len(builds) != 0 {
				t.Fatalf("malformed or conflicting catalog accepted: %+v, %v", builds, err)
			}
		})
	}
}

func TestCatalogPreservesUnknownArchitecturesAndUpdateOnlyRecords(t *testing.T) {
	for _, host := range []model.Host{
		{ProcessArchitecture: model.ArchitectureX86, NativeArchitecture: model.ArchitectureX86},
		{ProcessArchitecture: model.ArchitectureAMD64, NativeArchitecture: model.ArchitectureAMD64},
		{ProcessArchitecture: model.ArchitectureARM64, NativeArchitecture: model.ArchitectureARM64},
	} {
		t.Run(string(host.NativeArchitecture), func(t *testing.T) {
			// Discovery deliberately has no host parameter: every host consumes the same complete list.
			s := serveJSON(t, fixture(t, "builds-sparse.json"))
			builds, err := New(s.Client(), s.URL).Search(context.Background(), "")
			if err != nil {
				t.Fatal(err)
			}
			if len(builds) != 3 || builds[1].Architecture != "arm" || builds[0].UpdateID != sourceID {
				t.Fatalf("host %s lost unknown/update-only target: %+v", host.NativeArchitecture, builds)
			}
		})
	}
}

func TestRevisionQualifiedIDsRoundTrip(t *testing.T) {
	id := "5486793c-ef16-4f21-b397-f0321a833424_rev.2"
	var paths []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Query().Get("id") != id {
			t.Errorf("request changed revision: %q", r.URL.Query().Get("id"))
		}
		switch r.URL.Path {
		case "/listlangs.php":
			_, _ = w.Write(fixture(t, "languages.json"))
		case "/listeditions.php":
			if r.URL.Query().Get("lang") != "en-us" {
				t.Error("missing language")
			}
			_, _ = w.Write(fixture(t, "editions.json"))
		case "/get.php":
			if r.URL.Query().Get("lang") != "en-us" || r.URL.Query().Get("edition") != "updateonly" {
				t.Error("missing selection")
			}
			_, _ = w.Write(fixture(t, "files-nolinks.json"))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer s.Close()
	c := New(s.Client(), s.URL)
	c.MetadataOnly = true
	langs, err := c.Languages(context.Background(), id)
	if err != nil || len(langs) != 38 {
		t.Fatalf("languages: %d, %v", len(langs), err)
	}
	editions, err := c.Editions(context.Background(), id, "en-us")
	if err != nil || len(editions) != 2 || editions[0].ID != "PROFESSIONAL" {
		t.Fatalf("editions: %+v, %v", editions, err)
	}
	files, err := c.Files(context.Background(), id, "en-us", "updateonly")
	if err != nil {
		t.Fatal(err)
	}
	if files.Source.UpdateID != id {
		t.Fatalf("source identity rewritten: %+v", files.Source)
	}
	if len(paths) != 3 {
		t.Fatalf("want full endpoint walk, got %v", paths)
	}
	if _, err := json.Marshal(files); err != nil {
		t.Fatalf("public metadata serialization: %v", err)
	}
}
