package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"uupbuilder/internal/metadata/privatestore"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

// Independently implemented from the pinned WIM header/resource/blob-table
// disk definitions (v1.14.5). Only uncompressed standard, single-image WIM.
var disk = binary.LittleEndian

func putDescriptor(b []byte, size, offset uint64, flags byte) {
	disk.PutUint64(b, size)
	b[7] = flags
	disk.PutUint64(b[8:], offset)
	disk.PutUint64(b[16:], size)
}

type readBudget struct{ used, limit uint64 }

func (b *readBudget) charge(n uint64) error {
	if n > b.limit-b.used {
		return ErrLimit
	}
	b.used += n
	return nil
}

type countedReader struct {
	ctx context.Context
	r   io.ReaderAt
	b   *readBudget
}

func (r countedReader) ReadAt(b []byte, off int64) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	if e := r.b.charge(uint64(len(b))); e != nil {
		return 0, e
	}
	return r.r.ReadAt(b, off)
}
func hashCopy(ctx context.Context, w io.Writer, r io.ReaderAt, size uint64) (string, string, error) {
	h1, h256 := sha1.New(), sha256.New()
	var b [64 << 10]byte
	for off := uint64(0); off < size; {
		if e := ctx.Err(); e != nil {
			return "", "", e
		}
		n := min(uint64(len(b)), size-off)
		got, e := r.ReadAt(b[:n], int64(off))
		if e != nil || uint64(got) != n {
			return "", "", errors.Join(ErrIntegrity, e)
		}
		h1.Write(b[:n])
		h256.Write(b[:n])
		if w != nil {
			got, e = w.Write(b[:n])
			if e != nil || uint64(got) != n {
				return "", "", errors.Join(io.ErrShortWrite, e)
			}
		}
		off += n
	}
	return hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(h256.Sum(nil)), ctx.Err()
}
func shape(in writeInput, l Limits) (sum, total uint64, e error) {
	if len(in.Resources) == 0 || len(in.Resources) > l.MaxResources || len(in.XML) == 0 || len(in.XML) > l.MaxXMLBytes || len(in.XML)%2 != 0 || l.MaxBufferBytes < 64<<10 || in.CheckLive == nil || in.HeaderFlags & ^uint32(0x80) != 0 {
		return 0, 0, ErrLimit
	}
	// Conservatively includes two record slices, map keys, and serialized framing.
	if uint64(len(in.Resources))*1024+uint64(len(in.XML))*8+4096 > l.MaxResultBytes {
		return 0, 0, ErrLimit
	}
	seen := make(map[string]bool, len(in.Resources))
	for n, r := range in.Resources {
		a, e1 := hex.DecodeString(r.SHA1)
		c, e2 := hex.DecodeString(r.SHA256)
		if e1 != nil || e2 != nil || len(a) != 20 || len(c) != 32 || r.Size == 0 || r.Reader == nil || r.References == 0 || r.Metadata != (n == 0) || seen[r.SHA1] {
			return 0, 0, ErrInput
		}
		seen[r.SHA1] = true
		if r.Size > l.MaxOutputBytes-sum {
			return 0, 0, ErrLimit
		}
		sum += r.Size
	}
	overhead := uint64(208 + len(in.Resources)*50 + len(in.XML))
	if overhead > l.MaxOutputBytes-sum {
		return 0, 0, ErrLimit
	}
	total = sum + overhead
	// Initial source streaming, final source reread, output resource/framing
	// verification, whole-output identity and retained-file custody verification.
	if 2*sum+3*total > l.MaxReadBytes {
		return 0, 0, ErrLimit
	}
	return sum, total, nil
}
func writeStandard(ctx context.Context, in writeInput, limits Limits) (result *Artifact, runErr error) {
	if ctx == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	l, e := bounds(limits)
	if e != nil {
		return nil, e
	}
	sum, total, e := shape(in, l)
	if e != nil {
		return nil, e
	}
	if e = in.CheckLive(); e != nil {
		return nil, e
	}
	volume, e := platform.InspectStorage(os.TempDir())
	if e != nil {
		return nil, e
	}
	if total > volume.MaxFileBytes || total > volume.AvailableBytes || 64<<20 > volume.AvailableBytes-total {
		return nil, ErrLimit
	}
	store, e := privatestore.New(privatestore.Profile{MaxFiles: 1, MaxBytes: total}, "canonical-standard-wim")
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			runErr = errors.Join(runErr, store.Close())
		}
	}()
	f, name, e := store.Create(total)
	if e != nil {
		return nil, e
	}
	open := true
	defer func() {
		if open {
			runErr = errors.Join(runErr, f.Close())
		}
	}()
	lookup := 208 + sum
	xmlOff := lookup + uint64(len(in.Resources))*50
	var header [208]byte
	copy(header[:], "MSWIM\x00\x00\x00")
	disk.PutUint32(header[8:], 208)
	disk.PutUint32(header[12:], 0x10d00)
	disk.PutUint32(header[16:], in.HeaderFlags)
	if _, e = rand.Read(header[24:40]); e != nil {
		return nil, e
	}
	disk.PutUint16(header[40:], 1)
	disk.PutUint16(header[42:], 1)
	disk.PutUint32(header[44:], 1)
	putDescriptor(header[48:], uint64(len(in.Resources))*50, lookup, 2)
	putDescriptor(header[72:], uint64(len(in.XML)), xmlOff, 2)
	if _, e = f.Write(header[:]); e != nil {
		return nil, e
	}
	budget := &readBudget{limit: l.MaxReadBytes}
	for _, r := range in.Resources {
		a, b, e := hashCopy(ctx, f, countedReader{ctx, r.Reader, budget}, r.Size)
		if e != nil || a != r.SHA1 || b != r.SHA256 {
			return nil, errors.Join(ErrIntegrity, e)
		}
	}
	off := uint64(208)
	for _, r := range in.Resources {
		var record [50]byte
		flags := byte(0)
		if r.Metadata {
			flags = 2
		}
		putDescriptor(record[:], r.Size, off, flags)
		disk.PutUint16(record[24:], 1)
		disk.PutUint32(record[26:], r.References)
		h, _ := hex.DecodeString(r.SHA1)
		copy(record[30:], h)
		if _, e = f.Write(record[:]); e != nil {
			return nil, e
		}
		off += r.Size
	}
	if _, e = f.Write(in.XML); e != nil {
		return nil, e
	}
	if e = f.Sync(); e != nil {
		return nil, e
	}
	e = f.Close()
	open = false
	if e != nil {
		return nil, e
	}
	retained, e := store.Retain(name, total)
	if e != nil {
		return nil, e
	}
	receipt, e := verifyStandard(ctx, countedReader{ctx, retained, budget}, total, in, l)
	if e != nil {
		return nil, e
	}
	for _, r := range in.Resources {
		a, b, e := hashCopy(ctx, nil, countedReader{ctx, r.Reader, budget}, r.Size)
		if e != nil || a != r.SHA1 || b != r.SHA256 {
			return nil, errors.Join(ErrIntegrity, e)
		}
	}
	if e = budget.charge(total); e != nil {
		return nil, e
	}
	if e = retained.Verify(ctx, model.DigestSHA256, receipt.SHA256, receipt.SHA256); e != nil {
		return nil, e
	}
	if e = store.Verify(ctx); e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = in.CheckLive(); e != nil {
		return nil, e
	}
	receipt.ReadBytes = budget.used
	receipt.RecipeDigest = in.RecipeDigest
	receipt.ProofDigest = in.ProofDigest
	result = &Artifact{store: store, file: retained, name: name, receipt: receipt}
	ok = true
	return result, nil
}
