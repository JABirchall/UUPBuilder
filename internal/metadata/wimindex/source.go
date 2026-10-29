package wimindex

import (
	"context"
	"errors"
	"os"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/localsource"
	"uupbuilder/internal/model"
)

type sourceView struct {
	ctx      context.Context
	file     *os.File
	path     string
	identity model.PayloadIdentity
	initial  os.FileInfo
}

func openSource(ctx context.Context, r metadata.LocalResource) (*sourceView, error) {
	f, info, e := localsource.Open(r.Path, r.Identity)
	if e != nil {
		return nil, sourceError(e)
	}
	return &sourceView{ctx, f, r.Path, r.Identity, info}, nil
}
func (v *sourceView) ReadAt(b []byte, off int64) (int, error) {
	if e := v.ctx.Err(); e != nil {
		return 0, e
	}
	if off < 0 || off > v.identity.Size || int64(len(b)) > v.identity.Size-off {
		return 0, ErrLayout
	}
	n, e := v.file.ReadAt(b, off)
	if v.ctx.Err() != nil {
		return n, v.ctx.Err()
	}
	return n, e
}
func (v *sourceView) rehash() (string, error) {
	s, e := localsource.Verify(v.ctx, v.file, v.path, v.identity, v.initial)
	return s, sourceError(e)
}
func sourceError(e error) error {
	if errors.Is(e, localsource.ErrInput) {
		return ErrInput
	}
	if errors.Is(e, localsource.ErrIntegrity) {
		return ErrIntegrity
	}
	return e
}
