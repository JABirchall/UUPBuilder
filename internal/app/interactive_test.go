package app

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
	"uupbuilder/internal/tui"
)

func TestInteractiveUsesExactSelectedConfigPath(t *testing.T) {
	want := filepath.Join(t.TempDir(), "explicit", "selected.toml")
	seen := ""
	options := append(headlessProgramOptions(), tea.WithFilter(func(workspace tea.Model, _ tea.Msg) tea.Msg {
		seen = workspace.(tui.Model).Snapshot().ConfigPath
		return tea.Quit()
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := runInteractive(ctx, Options{ConfigPath: want, Config: config.Defaults(), Dependencies: tui.Dependencies{ConfigPath: "wrong.toml", Catalog: startupCatalog{search: func(context.Context, string) ([]catalog.Build, error) { return nil, nil }}}}, options...)
	if err != nil || seen != want {
		t.Fatalf("selected config path = %q, want %q; error = %v", seen, want, err)
	}
}

func TestInteractiveCancellationClosesDiscovery(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan error, 1)
	abort := make(chan struct{})
	t.Cleanup(func() { close(abort) })
	deps := tui.Dependencies{Context: context.Background(), Catalog: startupCatalog{
		search: func(ctx context.Context, _ string) ([]catalog.Build, error) {
			close(started)
			select {
			case <-ctx.Done():
				stopped <- ctx.Err()
				return nil, ctx.Err()
			case <-abort:
				return nil, errors.New("test ended")
			}
		},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- runInteractive(ctx, Options{Config: config.Defaults(), Dependencies: deps}, headlessProgramOptions()...)
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("Workspace discovery never started")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("interactive cancellation = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Bubble Tea did not stop after cancellation")
	}
	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("discovery cancellation = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("interactive shutdown left discovery running")
	}
}

func TestInteractiveQuitClosesDiscovery(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan error, 1)
	abort := make(chan struct{})
	t.Cleanup(func() { close(abort) })
	cfg := config.Defaults()
	cfg.Image.UpdateID = "11111111-1111-1111-1111-111111111111_rev.7"
	deps := tui.Dependencies{Catalog: startupCatalog{
		search: func(context.Context, string) ([]catalog.Build, error) {
			select {
			case <-started:
			case <-abort:
			}
			return nil, nil
		},
		languages: func(ctx context.Context, _ string) ([]catalog.Language, error) {
			close(started)
			select {
			case <-ctx.Done():
				stopped <- ctx.Err()
				return nil, ctx.Err()
			case <-abort:
				return nil, errors.New("test ended")
			}
		},
	}}
	options := append(headlessProgramOptions(), tea.WithFilter(func(_ tea.Model, msg tea.Msg) tea.Msg {
		select {
		case <-started:
			return tea.Quit()
		default:
			return msg
		}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runInteractive(ctx, Options{Config: cfg, Dependencies: deps}, options...); err != nil {
		t.Fatalf("ordinary Workspace quit = %v", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("quit required caller cancellation: %v", ctx.Err())
	}
	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("discovery cleanup = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ordinary quit left discovery running")
	}
}

func headlessProgramOptions() []tea.ProgramOption {
	return []tea.ProgramOption{tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithoutRenderer(), tea.WithoutSignalHandler()}
}

type startupCatalog struct {
	search    func(context.Context, string) ([]catalog.Build, error)
	languages func(context.Context, string) ([]catalog.Language, error)
}

func (c startupCatalog) Search(ctx context.Context, query string) ([]catalog.Build, error) {
	return c.search(ctx, query)
}

func (c startupCatalog) Languages(ctx context.Context, id string) ([]catalog.Language, error) {
	if c.languages != nil {
		return c.languages(ctx, id)
	}
	return nil, errors.New("unexpected language request")
}

func (c startupCatalog) Editions(context.Context, string, string) ([]catalog.Edition, error) {
	return nil, errors.New("unexpected edition request")
}
