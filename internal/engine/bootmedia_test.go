package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"
	"uupbuilder/internal/engine/source"
)

func TestBootMediaBindsActualBootPredecessorAndKeepsInstallGap(t *testing.T) {
	ctx := context.Background()
	in, media, _, closeParents := setupFixture(t, setupFixtureOptions{})
	r, e := source.BindSetupBoot(ctx, in, media, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	boot, e := BuildSetupBoot(ctx, r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { boot.Close() })
	files, e := MaterializeMediaTree(ctx, media, MediaTreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { files.Close() })
	closeParents()
	joined, e := BindBootMedia(ctx, files, boot)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { joined.Close() })
	receipt := joined.Receipt()
	if receipt.Complete || receipt.NativeFilesystemPreservation || !receipt.ArchiveBytesVerified || len(receipt.MissingImages) != 1 || receipt.MissingImages[0] != "sources/install.wim" || receipt.BootSHA256 != boot.Receipt().Archive.SHA256 || receipt.MediaDigest != files.Receipt().Digest {
		t.Fatal("false assembly or unbound predecessors", receipt)
	}
	f, e := joined.Open("SOURCES/BOOT.WIM")
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(f)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(body)
	if hex.EncodeToString(h[:]) != receipt.BootSHA256 {
		t.Fatal("wrong boot bytes")
	}
	f, e = joined.Open("sources/lang.ini")
	if e != nil {
		t.Fatal(e)
	}
	body, e = io.ReadAll(f)
	if e != nil || !bytes.Equal(body, []byte("[Available UI Languages]\r\nen-US = 3\r\n")) {
		t.Fatal("wrong source media bytes", e)
	}
	if _, e = joined.Open("sources/install.wim"); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("missing image accepted", e)
	}
	receipt.MissingImages[0] = "caller mutation"
	if joined.Receipt().MissingImages[0] != "sources/install.wim" {
		t.Fatal("mutable assembly evidence")
	}
	f, e = joined.Open("sources/boot.wim")
	if e != nil {
		t.Fatal(e)
	}
	files.Close()
	if _, e = f.Read(make([]byte, 1)); !errors.Is(e, os.ErrClosed) {
		t.Fatal("borrower hid predecessor revocation", e)
	}
}
func TestBootMediaRejectsForeignMissingRevokedAndCancellation(t *testing.T) {
	ctx := context.Background()
	in, media, _, _ := setupFixture(t, setupFixtureOptions{})
	r, e := source.BindSetupBoot(ctx, in, media, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	boot, e := BuildSetupBoot(ctx, r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { boot.Close() })
	_, foreign, _, _ := setupFixture(t, setupFixtureOptions{launch: "different-source"})
	files, e := MaterializeMediaTree(ctx, foreign, MediaTreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { files.Close() })
	if a, e := BindBootMedia(ctx, files, boot); a != nil || !errors.Is(e, ErrInput) {
		t.Fatal("foreign source joined", e)
	}
	if a, e := BindBootMedia(ctx, nil, boot); a != nil || !errors.Is(e, ErrInput) {
		t.Fatal("missing media joined", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if a, e := BindBootMedia(canceled, files, boot); a != nil || e != context.Canceled {
		t.Fatal("canceled binding", e)
	}
	files.Close()
	if a, e := BindBootMedia(ctx, files, boot); a != nil || !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed media joined", e)
	}
}
