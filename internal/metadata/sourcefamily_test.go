package metadata

import (
	"context"
	"testing"
)

// No examined AppX metadata must remain an explicit app inventory gap, never
// silently assert that this source has no apps or has complete edition rules.
func TestUnexaminedAppInventoryRemainsExplicitGap(t *testing.T) {
	file := inputFile(t, "metadata.xml", `<WIM/>`, FormatWIMXML)
	inv, err := Inspect(context.Background(), requestFor(t, file))
	if err != nil {
		t.Fatal(err)
	}
	for _, gap := range inv.Gaps {
		if gap.Code == "app-inventory-unresolved" {
			return
		}
	}
	t.Fatal("unexamined app inventory was silently treated as empty")
}
