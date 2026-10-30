package app

import (
	"testing"
	"uupbuilder/internal/model"
)

func TestMediaRoutingRetainsAnyValidSourceSelection(t *testing.T) {
	for _, selection := range []model.Selection{
		{UpdateID: "6c7bf258-2632-47dd-83ee-c23945978da1", Architecture: "amd64", Language: "en-us", Editions: []string{"PROFESSIONAL"}},
		{UpdateID: "different-future-source", Architecture: "arm64", Language: "ja-jp", Editions: []string{"Core"}},
		{UpdateID: "older-source", Architecture: "x86", Language: "de-de", Editions: []string{"Professional", "Enterprise"}},
	} {
		if !selectedRequest(selection) {
			t.Errorf("valid selected source bypassed executable media preparation: %+v", selection)
		}
	}
}
