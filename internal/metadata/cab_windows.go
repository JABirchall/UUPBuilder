package metadata

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	native "golang.org/x/sys/windows"
	platform "uupbuilder/internal/platform/windows"
)

// ReadCABMetadata extracts exact prevalidated metadata members using the
// installed OS expand executable. No source executable or shell is launched.
// Each invocation owns a protected W1 scope; only its known files are removed.
func ReadCABMetadata(ctx context.Context, body []byte, names []string) (result map[string][]byte, err error) {
	inv, err := InspectCAB(ctx, body)
	if err != nil {
		return nil, err
	}
	ctx, stop := context.WithTimeout(ctx, 45*time.Second)
	defer stop()
	members := map[string]CABMember{}
	for _, m := range inv.Members {
		members[m.Name] = m
	}
	requested := map[string]bool{}
	for _, name := range names {
		if _, ok := members[name]; !ok || requested[name] || !(strings.HasSuffix(strings.ToLower(name), ".xml") || strings.HasSuffix(strings.ToLower(name), ".xml.cab")) {
			return nil, ErrInvalidInput
		}
		requested[name] = true
	}
	if len(names) == 0 {
		return nil, ErrInvalidInput
	}
	system, err := native.GetSystemDirectory()
	if err != nil {
		return nil, ErrInvalidInput
	}
	workspace, err := platform.CreateWorkspace(os.TempDir(), "app-metadata")
	if err != nil {
		return nil, ErrInvalidInput
	}
	// Open the parent and scope before work. Cleanup uses rooted single-entry
	// removes, never a recursive delete or a path obtained from the cabinet.
	parent, openErr := os.OpenRoot(filepath.Dir(workspace.Path()))
	if openErr != nil {
		workspace.Close()
		return nil, ErrInvalidInput
	}
	root, openErr := os.OpenRoot(workspace.Path())
	if openErr != nil {
		parent.Close()
		workspace.Close()
		return nil, ErrInvalidInput
	}
	var created []string
	defer func() {
		for i := len(created) - 1; i >= 0; i-- {
			e := workspace.Remove(created[i])
			if e != nil && !os.IsNotExist(e) {
				err = errors.Join(err, ErrInvalidInput)
			}
		}
		// The marker and directory belong to this fresh scope. Refuse to remove a
		// nonempty scope; unexpected resources are retained and reported.
		entries, e := cabReadDir(root, ".")
		if e == nil && len(entries) == 1 && entries[0].Name() == ".uupbuilder-owner.json" {
			e = root.Remove(".uupbuilder-owner.json")
		} else if e == nil {
			e = ErrInvalidInput
		}
		err = errors.Join(err, e, root.Close(), workspace.Close())
		if e == nil {
			if removeErr := parent.Remove(filepath.Base(workspace.Path())); removeErr != nil {
				err = errors.Join(err, ErrInvalidInput)
			}
		}
		err = errors.Join(err, parent.Close())
	}()
	f, err := workspace.OpenFile("input.cab", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, ErrInvalidInput
	}
	created = append(created, "input.cab")
	_, writeErr := f.Write(body)
	if closeErr := f.Close(); writeErr != nil || closeErr != nil {
		return nil, ErrInvalidInput
	}
	result = map[string][]byte{}
	for i, name := range names {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		directory := "out" + strconv.Itoa(i)
		if err = workspace.MkdirAll(directory); err != nil {
			return nil, ErrInvalidInput
		}
		created = append(created, directory)
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, runErr := platform.NewRunner().Run(bounded, platform.Invocation{Executable: filepath.Join(system, "expand.exe"), Arguments: []string{"input.cab", "-F:" + name, directory}, Workspace: workspace, JobID: workspace.Identity().JobID, OperationID: "read-metadata", Cancellation: platform.CancelTerminateTree}, nil)
		cancel()
		if runErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrMalformedMetadata
		}
		// Single-file cabinets may preserve the input .cab basename. The bytes,
		// exact count and declared size still bind the selected table member.
		entries, readErr := cabReadDir(root, directory)
		if readErr != nil || len(entries) != 1 {
			return nil, ErrMalformedMetadata
		}
		actual := entries[0].Name()
		if actual != name && actual != "input.cab" {
			return nil, ErrMalformedMetadata
		}
		relative := directory + "/" + actual
		created = append(created, relative)
		file, readErr := workspace.OpenFile(relative, os.O_RDONLY, 0)
		if readErr != nil {
			return nil, ErrMalformedMetadata
		}
		stat, statErr := file.Stat()
		if statErr != nil || !stat.Mode().IsRegular() || stat.Size() != int64(members[name].Size) {
			file.Close()
			return nil, ErrIntegrity
		}
		var info native.ByHandleFileInformation
		if native.GetFileInformationByHandle(native.Handle(file.Fd()), &info) != nil || info.FileAttributes&native.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 {
			file.Close()
			return nil, ErrIntegrity
		}
		data, readErr := io.ReadAll(io.LimitReader(contextReader{ctx, file}, int64(members[name].Size)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) != members[name].Size {
			return nil, ErrIntegrity
		}
		result[name] = data
	}
	return result, nil
}

func cabReadDir(root *os.Root, name string) ([]os.DirEntry, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(1025)
}
