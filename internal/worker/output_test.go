package worker

import (
	"context"
	"testing"
	"uupbuilder/internal/planner"
)

func TestOnlyConcretePublicationHandlerEnablesBoundary(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(planner.PublishISO, Handler{Run: func(context.Context, Stage) (Result, error) { return Result{}, nil }})
	if r.SupportsPublication() {
		t.Fatal("arbitrary no-op handler can enable publication")
	}
	r = NewRegistry()
	_ = r.Register(planner.PublishISO, PublicationHandler(nil))
	if r.SupportsPublication() {
		t.Fatal("nil provider enables publication")
	}
}
