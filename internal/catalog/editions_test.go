package catalog

import (
	"context"
	"testing"
)

func TestEditionsRetainFutureAndUpdateOnlyChoices(t *testing.T) {
	s := serveJSON(t, []byte(`{"response":{"editionList":["UPDATEONLY","FUTURE_EDITION"],"editionFancyNames":{"UPDATEONLY":"Updates only"}}}`))
	editions, err := New(s.Client(), s.URL).Editions(context.Background(), sourceID, "en-us")
	if err != nil || len(editions) != 2 || editions[0].ID != "UPDATEONLY" || editions[0].Name != "Updates only" || editions[1].Name != "FUTURE_EDITION" {
		t.Fatalf("lost selectable edition: %+v %v", editions, err)
	}
}
