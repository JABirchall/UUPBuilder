//go:build windows

package download

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"uupbuilder/internal/model"
	windows "uupbuilder/internal/platform/windows"
)

// Validators are hashed, not persisted verbatim: arbitrary server headers can
// contain signed URLs. Range responses must repeat this validator and the exact
// requested interval before any bytes are appended. No If-Range is necessary.
type resumeRecord struct {
	Version       int    `json:"version"`
	Key           string `json:"key"`
	ValidatorKind string `json:"validator_kind"`
	ValidatorHash string `json:"validator_hash"`
}

func rangeHeader(offset int64) string { return "bytes=" + strconv.FormatInt(offset, 10) + "-" }

func parseContentRange(value string) (start, end, total int64, err error) {
	bad := func() (int64, int64, int64, error) { return 0, 0, 0, errRestart }
	if !strings.HasPrefix(value, "bytes ") {
		return bad()
	}
	interval, size, ok := strings.Cut(strings.TrimPrefix(value, "bytes "), "/")
	if !ok {
		return bad()
	}
	lo, hi, ok := strings.Cut(interval, "-")
	if !ok {
		return bad()
	}
	start, err = strictInt(lo)
	if err != nil {
		return bad()
	}
	end, err = strictInt(hi)
	if err != nil {
		return bad()
	}
	total, err = strictInt(size)
	if err != nil || start > end || end >= total {
		return bad()
	}
	return start, end, total, nil
}
func strictInt(s string) (int64, error) {
	if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errRestart
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, errRestart
	}
	return n, nil
}
func unsatisfiedTotal(value string) (int64, error) {
	if !strings.HasPrefix(value, "bytes */") {
		return 0, errRestart
	}
	return strictInt(strings.TrimPrefix(value, "bytes */"))
}

func responseValidator(header http.Header) (string, string) {
	tag := header.Get("ETag")
	if strongETag(tag) {
		return "etag", hashString(tag)
	}
	modified, modifiedErr := http.ParseTime(header.Get("Last-Modified"))
	date, dateErr := http.ParseTime(header.Get("Date"))
	// RFC 9110 8.8.2.2 requires evidence that a date validator is strong.
	// Conservatively allow a minute for clock uncertainty between these fields.
	if modifiedErr == nil && dateErr == nil && date.Sub(modified) >= time.Minute {
		return "last-modified", hashString(modified.UTC().Format(http.TimeFormat))
	}
	return "", ""
}

func strongETag(tag string) bool {
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return false
	}
	for _, b := range []byte(tag[1 : len(tag)-1]) {
		if b != 0x21 && (b < 0x23 || b == 0x7f) {
			return false
		}
	}
	return true
}
func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func readJSON(root *windows.Workspace, name string, value any) error {
	f, err := root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 {
		return ErrStorage
	}
	return json.Unmarshal(b, value)
}
func writeJSON(root *windows.Workspace, name string, value any) error {
	b, err := json.Marshal(value)
	if err != nil || len(b) > 65536 {
		return ErrStorage
	}
	tmp := name + ".tmp"
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return ErrStorage
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrStorage
	}
	if root.Replace(tmp, name, true) != nil {
		return ErrStorage
	}
	return nil
}

func loadResume(root *windows.Workspace, id model.PayloadIdentity, f *os.File) (resumeRecord, int64, error) {
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return resumeRecord{}, 0, ErrStorage
	}
	key := id.Key()
	var record resumeRecord
	if readJSON(root, key+".resume.json", &record) != nil || record.Version != 1 || record.Key != key ||
		(record.ValidatorKind != "etag" && record.ValidatorKind != "last-modified") ||
		(model.Digest{Algorithm: model.DigestSHA256, Value: record.ValidatorHash}).Validate() != nil || stat.Size() > id.Size {
		if err := resetPartial(root, key, f); err != nil {
			return resumeRecord{}, 0, err
		}
		return resumeRecord{}, 0, nil
	}
	return record, stat.Size(), nil
}

func resetPartial(root *windows.Workspace, key string, f *os.File) error {
	if f.Truncate(0) != nil {
		return ErrStorage
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return ErrStorage
	}
	if err := root.Remove(key + ".resume.json"); err != nil && !os.IsNotExist(err) {
		return ErrStorage
	}
	return nil
}
