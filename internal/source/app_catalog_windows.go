package source

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// SourceAppCatalog owns no startup files. Loads are serialized with cancelable
// admission; only the most recent, fully verified metadata CAB is cached in
// memory. Locators live only on the active Load stack and never enter snapshots.
type SourceAppCatalog struct {
	Emit             model.Emit
	metadata, online *catalog.Client
	http             *http.Client
	gate             chan struct{}
	bodyCooldown     map[string]time.Time
	cachedID         model.PayloadIdentity
	cachedCAB        []byte
}

func NewAppCatalog(endpoint string) *SourceAppCatalog {
	c := &SourceAppCatalog{gate: make(chan struct{}, 1), bodyCooldown: make(map[string]time.Time)}
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || !appURL(req.URL) {
			return ErrInvalidInput
		}
		return nil
	}}
	client.Transport = &appBodyTransport{owner: c, base: http.DefaultTransport}
	offline := catalog.New(client, endpoint)
	offline.MetadataOnly = true
	offline.MaxBodyBytes = 4 << 20
	online := catalog.New(client, endpoint)
	online.MaxBodyBytes = 4 << 20
	c.metadata, c.online, c.http = offline, online, client
	return c
}

type appBodyRequest struct{}

// Check each actual CAB request, including redirected requests, against the
// origin that will receive it. Catalog calls have their separate shared pacer.
type appBodyTransport struct {
	owner *SourceAppCatalog
	base  http.RoundTripper
}

func (t *appBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Context().Value(appBodyRequest{}) == nil {
		return t.base.RoundTrip(req)
	}
	origin := strings.ToLower(req.URL.Scheme + "://" + req.URL.Host)
	if err := t.owner.waitBody(req.Context(), origin); err != nil {
		return nil, err
	}
	resp, err := t.base.RoundTrip(req)
	if err == nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) {
		t.owner.observeBodyRetryAfter(origin, resp.Header.Get("Retry-After"))
	}
	return resp, err
}

// CAB Retry-After belongs to the payload origin, independently of get.php.
// Load's admission gate protects this state and the private verified CAB cache.
func (c *SourceAppCatalog) observeBodyRetryAfter(origin, raw string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return
	}
	now := time.Now()
	var until time.Time
	const maxDelay = time.Duration(1<<63 - 1)
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		delay := maxDelay
		if seconds <= uint64(maxDelay/time.Second) {
			delay = time.Duration(seconds) * time.Second
		}
		until = now.Add(delay)
	} else if strings.Trim(value, "0123456789") == "" {
		// Numeric overflow is still a server delay, never permission to send.
		until = now.Add(maxDelay)
	} else if date, err := http.ParseTime(value); err == nil {
		until = date
	}
	if until.After(c.bodyCooldown[origin]) {
		c.bodyCooldown[origin] = until
	}
}
func appURL(u *url.URL) bool {
	return u != nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil && u.Fragment == ""
}
func (c *SourceAppCatalog) waitBody(ctx context.Context, origin string) error {
	next := c.bodyCooldown[origin]
	delay := time.Until(next)
	if delay > 2*time.Minute {
		return &catalog.RetryLaterError{RetryAt: next}
	}
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ctx.Err()
}

func (c *SourceAppCatalog) Load(ctx context.Context, selection model.Selection) (result AppCatalogSnapshot, err error) {
	result = AppCatalogSnapshot{Selection: selection, State: AppCatalogDeferred}
	result.Selection.Editions = slices.Clone(selection.Editions)
	if ctx == nil || selection.Validate() != nil || c == nil || c.gate == nil || c.metadata == nil || c.online == nil || c.http == nil || len(selection.Editions) > 64 {
		return result, ErrInvalidInput
	}
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	case c.gate <- struct{}{}:
	}
	defer func() {
		<-c.gate
		result = result.Clone()
		if err != nil {
			err = portError(ctx, "app metadata", err)
		}
	}()
	if c.Emit != nil {
		c.Emit(model.Event{StageID: "app-metadata", Kind: model.EventStage, Message: "Reading selected app composition metadata"})
	}
	editions, err := c.metadata.Editions(ctx, selection.UpdateID, "neutral")
	if err != nil {
		return result, err
	}
	selector := ""
	for _, edition := range editions {
		if edition.ID == "APP" {
			selector = "APP"
			break
		}
		if edition.ID == "APP_MOMENT" {
			selector = "APP_MOMENT"
		}
	}
	if selector == "" {
		result.Gaps = []string{"This exact source advertises no neutral app selector; source app metadata remains unexamined."}
		return result, nil
	}
	result.AppQuery = model.SourceQuery{UpdateID: selection.UpdateID, Language: "neutral", Edition: selector}
	appSet, err := c.metadata.Files(ctx, selection.UpdateID, "neutral", selector)
	if err != nil {
		return result, err
	}
	if appSet.Source.UpdateID != selection.UpdateID || appSet.Source.Architecture != selection.Architecture || appSet.Source.Language != "neutral" {
		return result, ErrInputIdentityChanged
	}
	result.AppSource = appSet.Source
	result.AppManifest, _, err = Union(appSet.Source, []catalog.FileSet{appSet}, result.AppQuery)
	if err != nil {
		return result, err
	}
	cab, found := metadataCAB(appSet)
	if !found {
		result.Gaps = []string{"No single bounded aggregated metadata CAB is offered; app metadata remains unexamined."}
		return result, nil
	}
	result.CAB = cab.Identity
	var first catalog.FileSet
	for i, edition := range selection.Editions {
		set, fetchErr := c.metadata.Files(ctx, selection.UpdateID, selection.Language, edition)
		if fetchErr != nil {
			return result, fetchErr
		}
		expected := appSet.Source
		expected.Language = selection.Language
		if set.Source != expected {
			return result, ErrInputIdentityChanged
		}
		other, ok := metadataCAB(set)
		if !ok || other.Identity != cab.Identity {
			return result, ErrInputIdentityChanged
		}
		query := model.SourceQuery{UpdateID: selection.UpdateID, Language: selection.Language, Edition: edition}
		frozen, _, unionErr := Union(set.Source, []catalog.FileSet{set}, query)
		if unionErr != nil {
			return result, unionErr
		}
		result.SelectedManifests = append(result.SelectedManifests, frozen)
		if i == 0 {
			first = set
			result.SelectedSource = set.Source
		}
	}
	var body []byte
	if c.cachedID == cab.Identity && len(c.cachedCAB) > 0 {
		body = c.cachedCAB
	} else {
		online, fetchErr := c.online.Files(ctx, selection.UpdateID, selection.Language, selection.Editions[0])
		if fetchErr != nil {
			return result, fetchErr
		}
		query := result.SelectedManifests[0].Queries[0]
		frozen, locators, unionErr := Union(first.Source, []catalog.FileSet{online}, query)
		if unionErr != nil || frozen.Digest != result.SelectedManifests[0].Digest {
			return result, ErrInputIdentityChanged
		}
		locator, ok := locators[cab.Identity]
		if !ok {
			return result, ErrPayloadUnavailable
		}
		body, err = c.acquire(ctx, cab.Identity, locator)
		if err != nil {
			return result, err
		}
		c.cachedID = cab.Identity
		c.cachedCAB = body
	}
	// Cached bytes are private, but verify again before every OS decoder use.
	if !verifiedCAB(cab.Identity, body) {
		return result, metadata.ErrIntegrity
	}
	return observeAppCatalog(ctx, result, body)
}
func metadataCAB(set catalog.FileSet) (model.Payload, bool) {
	var match model.Payload
	count := 0
	for _, p := range set.Payloads {
		name := strings.ToLower(p.Destination)
		if strings.Contains(name, "aggregatedmetadata") && strings.HasSuffix(name, ".cab") {
			match = p
			count++
		}
	}
	return match, count == 1 && match.Identity.Size > 0 && match.Identity.Size <= metadata.MaxMetadataCABBytes
}
func verifiedCAB(id model.PayloadIdentity, body []byte) bool {
	if id.Validate() != nil || id.Size != int64(len(body)) || len(body) > metadata.MaxMetadataCABBytes {
		return false
	}
	switch id.Digest.Algorithm {
	case model.DigestSHA256:
		sum := sha256.Sum256(body)
		return hex.EncodeToString(sum[:]) == id.Digest.Value
	case model.DigestSHA1:
		sum := sha1.Sum(body)
		return hex.EncodeToString(sum[:]) == id.Digest.Value
	}
	return false
}
func (c *SourceAppCatalog) acquire(ctx context.Context, id model.PayloadIdentity, locator model.Locator) ([]byte, error) {
	if c.Emit != nil {
		c.Emit(model.Event{StageID: "app-metadata", Kind: model.EventLog, Message: "Acquiring app metadata: " + id.Provenance.Name})
	}
	u, err := url.Parse(locator.URL)
	if err != nil || !appURL(u) || !locator.ExpiresAt.IsZero() && !time.Now().Before(locator.ExpiresAt) {
		return nil, ErrPayloadUnavailable
	}
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	if err := c.waitBody(ctx, origin); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(context.WithValue(ctx, appBodyRequest{}, true), http.MethodGet, locator.URL, nil)
	if err != nil {
		return nil, ErrInvalidInput
	}
	req.Header.Set("User-Agent", "UUPBuilder/app-metadata")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, ErrPayloadUnavailable
	}
	defer resp.Body.Close()
	// No retries of body locators: upstream throttling is returned to the caller,
	// whose retry is deliberate. Catalogue retries honor its Retry-After policy.
	if resp.StatusCode != http.StatusOK || resp.ContentLength > id.Size {
		return nil, ErrPayloadUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, id.Size+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, ErrPayloadUnavailable
	}
	if !verifiedCAB(id, body) {
		return nil, metadata.ErrIntegrity
	}
	return body, nil
}

func observeAppCatalog(ctx context.Context, s AppCatalogSnapshot, body []byte) (AppCatalogSnapshot, error) {
	inventory, err := metadata.InspectCAB(ctx, body)
	if err != nil {
		return s, err
	}
	sum := sha256.Sum256(body)
	s.Containers = append(s.Containers, AppMetadataContainer{SHA256: hex.EncodeToString(sum[:]), Inventory: inventory})
	candidates := map[string]string{"desktoptargetcompdb_app_neutral.xml.cab": "app"}
	for _, edition := range s.Selection.Editions {
		candidates["desktoptargetcompdb_"+strings.ToLower(edition)+"_"+strings.ToLower(s.Selection.Language)+".xml.cab"] = edition
	}
	var names []string
	for _, member := range inventory.Members {
		if _, ok := candidates[strings.ToLower(member.Name)]; ok {
			names = append(names, member.Name)
		}
	}
	if len(names) != len(candidates) {
		s.Gaps = []string{"The aggregated metadata lacks the app/selected-edition CompDB candidates; applicability remains unexamined."}
		return s, nil
	}
	nested, err := metadata.ReadCABMetadata(ctx, body, names)
	if err != nil {
		return s, err
	}
	var app metadata.AppCompDBObservation
	var appRef metadata.DocumentReference
	type editionDoc struct {
		edition string
		doc     metadata.AppCompDBObservation
		ref     metadata.DocumentReference
	}
	var selected []editionDoc
	total := inventory.DecodedBytes
	for _, name := range names {
		raw := nested[name]
		inv, readErr := metadata.InspectCAB(ctx, raw)
		if readErr != nil {
			return s, readErr
		}
		digest := sha256.Sum256(raw)
		s.Containers = append(s.Containers, AppMetadataContainer{Member: name, SHA256: hex.EncodeToString(digest[:]), Inventory: inv})
		if len(inv.Members) != 1 || !strings.HasSuffix(strings.ToLower(inv.Members[0].Name), ".xml") {
			return s, metadata.ErrMalformedMetadata
		}
		total += inv.DecodedBytes
		if total > 128<<20 {
			return s, metadata.ErrLimit
		}
		member := inv.Members[0].Name
		xmls, readErr := metadata.ReadCABMetadata(ctx, raw, []string{member})
		if readErr != nil {
			return s, readErr
		}
		original := xmls[member]
		doc, parseErr := metadata.ObserveAppCompDB(ctx, original)
		if parseErr != nil {
			return s, parseErr
		}
		hash := sha256.Sum256(original)
		ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: s.CAB, Member: name + "/" + member}, SHA256: hex.EncodeToString(hash[:])}
		s.Documents = append(s.Documents, ref)
		role := candidates[strings.ToLower(name)]
		if role == "app" {
			app = doc
			appRef = ref
		} else {
			if !strings.EqualFold(doc.Edition, role) || !strings.EqualFold(doc.Language, s.Selection.Language) {
				return s, ErrInputIdentityChanged
			}
			selected = append(selected, editionDoc{role, doc, ref})
		}
	}
	if app.BuildID == "" || app.Architecture != s.Selection.Architecture || app.Edition != "" || app.Language != "" && !strings.EqualFold(app.Language, "neutral") {
		return s, ErrInputIdentityChanged
	}
	s.Binding = AppCompatibilityBinding{BuildID: app.BuildID, Architecture: app.Architecture, BaselineOSVersion: app.BaselineOSVersion}
	features := map[string]metadata.AppFeatureObservation{}
	for _, f := range app.Features {
		if f.Type == "MSIX" || f.Type == "MSIXBundle" || f.Type == "MSIXFramework" {
			features[f.FeatureID] = f
		}
	}
	entries := map[string]AppCatalogEntry{}
	for _, edition := range selected {
		if edition.doc.BuildID != app.BuildID || edition.doc.Architecture != app.Architecture || edition.doc.BaselineOSVersion != app.BaselineOSVersion {
			return s, ErrInputIdentityChanged
		}
		desktopCount := 0
		for _, f := range edition.doc.Features {
			if f.Type != "DesktopMedia" {
				continue
			}
			desktopCount++
			for _, dep := range f.Dependencies {
				if dep.Group != "PreinstalledApps" {
					continue
				}
				feature, ok := features[dep.FeatureID]
				if !ok {
					return s, metadata.ErrConflictingMetadata
				}
				entry := catalogEntry(feature, appRef)
				if old, exists := entries[dep.FeatureID]; exists {
					entry = old
				}
				entry.Editions = append(entry.Editions, AppEditionReference{Edition: edition.edition, Type: dep.Type, Selector: f.Selector + "/Dependencies/Feature[@FeatureID='" + dep.FeatureID + "']", Document: edition.ref})
				entries[dep.FeatureID] = entry
			}
		}
		if desktopCount != 1 {
			return s, metadata.ErrMalformedMetadata
		}
	}
	// Retain dependency observations, including frameworks, without asserting a
	// package-level dependency closure or promoting frameworks to app choices.
	queue := []string{}
	for id := range entries {
		queue = append(queue, id)
	}
	for index := 0; index < len(queue); index++ {
		entry := entries[queue[index]]
		for _, dep := range entry.Dependencies {
			if _, exists := entries[dep.FeatureID]; exists {
				continue
			}
			feature, ok := features[dep.FeatureID]
			if !ok {
				s.Gaps = append(s.Gaps, "Source feature dependency remains unresolved: "+dep.FeatureID)
				continue
			}
			entries[dep.FeatureID] = catalogEntry(feature, appRef)
			queue = append(queue, dep.FeatureID)
		}
	}
	for _, entry := range entries {
		s.Entries = append(s.Entries, entry)
	}
	sort.Slice(s.Entries, func(i, j int) bool { return s.Entries[i].FeatureID < s.Entries[j].FeatureID })
	s.State = AppCatalogAvailable
	s.Gaps = append(s.Gaps, "Manifest identity/Publisher, localized names, package architecture/language/version closure, licensing and provisioning applicability remain pending.")
	return s, nil
}
func catalogEntry(f metadata.AppFeatureObservation, ref metadata.DocumentReference) AppCatalogEntry {
	return AppCatalogEntry{FeatureID: f.FeatureID, Type: f.Type, Selector: f.Selector, Document: ref, Dependencies: f.Dependencies, Packages: f.Packages, Media: f.Media, InitialIntents: f.InitialIntents, Licenses: f.Licenses}
}

var _ AppCatalog = (*SourceAppCatalog)(nil)
