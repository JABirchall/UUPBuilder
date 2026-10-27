package model

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type Selection struct {
	UpdateID     string       `json:"update_id" toml:"update_id"`
	Architecture Architecture `json:"architecture" toml:"architecture"`
	Language     string       `json:"language" toml:"language"`
	Editions     []string     `json:"editions" toml:"editions"`
}

func (s Selection) Validate() error {
	if err := identifier("image.update_id", s.UpdateID); err != nil {
		return err
	}
	if err := s.Architecture.Validate(); err != nil {
		return err
	}
	if err := identifier("image.language", s.Language); err != nil {
		return err
	}
	if len(s.Editions) == 0 {
		return errors.New("image.editions: at least one edition is required")
	}
	return uniqueIdentifiers("image.editions", s.Editions)
}

type UpdatePolicy string

const (
	UpdatesIntegrate UpdatePolicy = "integrate"
	UpdatesExternal  UpdatePolicy = "external"
	UpdatesOmit      UpdatePolicy = "omit"
)

type ServicingStrategy string

const (
	ServicingAuto       ServicingStrategy = "auto"
	ServicingPerEdition ServicingStrategy = "per-edition"
	ServicingSharedBase ServicingStrategy = "shared-base"
)

type ExpansionPolicy string

const (
	ExpansionAuto     ExpansionPolicy = "auto"
	ExpansionExpand   ExpansionPolicy = "expand"
	ExpansionPreserve ExpansionPolicy = "preserve"
)

type InclusionPolicy string

const (
	InclusionAuto    InclusionPolicy = "auto"
	InclusionInclude InclusionPolicy = "include"
	InclusionOmit    InclusionPolicy = "omit"
)

type ResetBasePolicy string

const (
	ResetBaseOff  ResetBasePolicy = "off"
	ResetBaseAuto ResetBasePolicy = "auto"
	ResetBaseOn   ResetBasePolicy = "on"
)

type BootWIMEngine string

const (
	BootWIMAuto   BootWIMEngine = "auto"
	BootWIMWimlib BootWIMEngine = "wimlib"
	BootWIMDISM   BootWIMEngine = "dism"
)

type ReferenceImagePolicy string

const (
	ReferenceAuto   ReferenceImagePolicy = "auto"
	ReferenceReuse  ReferenceImagePolicy = "reuse"
	ReferenceExport ReferenceImagePolicy = "export"
)

type MSUPolicy string

const (
	MSUAuto   MSUPolicy = "auto"
	MSUExpand MSUPolicy = "expand"
	MSUKeep   MSUPolicy = "keep"
)

type DriverTarget string

const (
	DriverOS     DriverTarget = "os"
	DriverWinPE  DriverTarget = "winpe"
	DriverWinRE  DriverTarget = "winre"
	DriverShared DriverTarget = "shared"
)

type DriverSettings struct {
	Enabled bool           `json:"enabled" toml:"enabled"`
	Source  string         `json:"source" toml:"source"`
	Targets []DriverTarget `json:"targets" toml:"targets"`
}

type EditionSettings struct {
	Derived               []string          `json:"derived" toml:"derived"`
	Strategy              ServicingStrategy `json:"strategy" toml:"strategy"`
	PreserveRequiredBases bool              `json:"preserve_required_bases" toml:"preserve_required_bases"`
}

type ConversionSettings struct {
	Updates            UpdatePolicy         `json:"updates" toml:"updates"`
	ServicingStrategy  ServicingStrategy    `json:"servicing_strategy" toml:"servicing_strategy"`
	CumulativeUpdates  ExpansionPolicy      `json:"cumulative_update_policy" toml:"cumulative_update_policy"`
	CheckpointUpdates  ExpansionPolicy      `json:"checkpoint_updates" toml:"checkpoint_updates"`
	EnablementPackages InclusionPolicy      `json:"enablement_packages" toml:"enablement_packages"`
	Cleanup            bool                 `json:"cleanup" toml:"cleanup"`
	ResetBase          ResetBasePolicy      `json:"reset_base" toml:"reset_base"`
	NetFX3             bool                 `json:"netfx3" toml:"netfx3"`
	IncludeWinRE       bool                 `json:"include_winre" toml:"include_winre"`
	WinREUpdates       InclusionPolicy      `json:"winre_updates" toml:"winre_updates"`
	UpdateBootFiles    bool                 `json:"update_boot_files" toml:"update_boot_files"`
	BootWIMEngine      BootWIMEngine        `json:"boot_wim_engine" toml:"boot_wim_engine"`
	ReferenceImages    ReferenceImagePolicy `json:"reference_images" toml:"reference_images"`
	CumulativeMSU      MSUPolicy            `json:"cumulative_msu" toml:"cumulative_msu"`
	KeepReferenceESDs  bool                 `json:"keep_reference_esds" toml:"keep_reference_esds"`
	Drivers            DriverSettings       `json:"drivers" toml:"drivers"`
	Editions           EditionSettings      `json:"editions" toml:"editions"`
}

type AppMode string

const (
	AppsDefault AppMode = "default"
	AppsCustom  AppMode = "custom"
	AppsNone    AppMode = "none"
)

type AppStubPolicy string

const (
	AppStubAuto AppStubPolicy = "auto"
	AppStub     AppStubPolicy = "stub"
	AppFull     AppStubPolicy = "full"
)

type EdgePolicy string

const (
	EdgeDefault EdgePolicy = "default"
	EdgeInclude EdgePolicy = "include"
	EdgeExclude EdgePolicy = "exclude"
)

type AppSettings struct {
	Mode       AppMode       `json:"mode" toml:"mode"`
	Preset     string        `json:"preset" toml:"preset"`
	StubPolicy AppStubPolicy `json:"stub_policy" toml:"stub_policy"`
	Include    []string      `json:"include" toml:"include"`
	Edge       EdgePolicy    `json:"edge_policy" toml:"edge_policy"`
}

type OutputKind string

const (
	OutputISO       OutputKind = "iso"
	OutputImage     OutputKind = "image"
	OutputDirectory OutputKind = "directory"
)

type ImageFormat string

const (
	ImageWIM ImageFormat = "wim"
	ImageESD ImageFormat = "esd"
	ImageSWM ImageFormat = "swm"
)

type OutputSettings struct {
	Kind         OutputKind  `json:"kind" toml:"kind"`
	ImageFormat  ImageFormat `json:"image_format" toml:"image_format"`
	SplitSizeMiB int         `json:"split_size_mib" toml:"split_size_mib"`
	Directory    string      `json:"directory" toml:"directory"`
	Filename     string      `json:"filename" toml:"filename"`
	Label        string      `json:"label" toml:"label"`
	EditionOrder []string    `json:"edition_order" toml:"edition_order"`
}

type StorageSettings struct {
	Workspace         string `json:"workspace" toml:"workspace"`
	Cache             string `json:"cache" toml:"cache"`
	KeepDownloads     bool   `json:"keep_downloads" toml:"keep_downloads"`
	KeepIntermediates bool   `json:"keep_intermediates" toml:"keep_intermediates"`
}

type ProxyMode string

const (
	ProxySystem   ProxyMode = "system"
	ProxyDirect   ProxyMode = "direct"
	ProxyExplicit ProxyMode = "explicit"
)

// URL must not contain credentials; credential handling belongs to runtime
// configuration and must never enter a frozen settings snapshot or report.
type ProxySettings struct {
	Mode ProxyMode `json:"mode" toml:"mode"`
	URL  string    `json:"url,omitempty" toml:"url,omitempty"`
}

type DownloadSettings struct {
	ParallelFiles int           `json:"parallel_files" toml:"parallel_files"`
	Retries       int           `json:"retries" toml:"retries"`
	Proxy         ProxySettings `json:"proxy" toml:"proxy"`
}

// ResolvedSettings is the typed settings snapshot. Validate checks syntax and
// internal shape, never source/host support. Resolution must report each
// requested/effective policy through SettingApplicability; explicit requests
// are retained until they are supported or rejected with a concrete reason.
type ResolvedSettings struct {
	Conversion ConversionSettings `json:"conversion" toml:"conversion"`
	Apps       AppSettings        `json:"apps" toml:"apps"`
	Output     OutputSettings     `json:"output" toml:"output"`
	Storage    StorageSettings    `json:"storage" toml:"storage"`
	Downloads  DownloadSettings   `json:"downloads" toml:"downloads"`
}

func (s ResolvedSettings) Validate() error {
	c := s.Conversion
	checks := []error{
		enum("conversion.updates", c.Updates, UpdatesIntegrate, UpdatesExternal, UpdatesOmit),
		enum("conversion.servicing_strategy", c.ServicingStrategy, ServicingAuto, ServicingPerEdition, ServicingSharedBase),
		enum("conversion.cumulative_update_policy", c.CumulativeUpdates, ExpansionAuto, ExpansionExpand, ExpansionPreserve),
		enum("conversion.checkpoint_updates", c.CheckpointUpdates, ExpansionAuto, ExpansionExpand, ExpansionPreserve),
		enum("conversion.enablement_packages", c.EnablementPackages, InclusionAuto, InclusionInclude, InclusionOmit),
		enum("conversion.reset_base", c.ResetBase, ResetBaseOff, ResetBaseAuto, ResetBaseOn),
		enum("conversion.winre_updates", c.WinREUpdates, InclusionAuto, InclusionInclude, InclusionOmit),
		enum("conversion.boot_wim_engine", c.BootWIMEngine, BootWIMAuto, BootWIMWimlib, BootWIMDISM),
		enum("conversion.reference_images", c.ReferenceImages, ReferenceAuto, ReferenceReuse, ReferenceExport),
		enum("conversion.cumulative_msu", c.CumulativeMSU, MSUAuto, MSUExpand, MSUKeep),
		enum("conversion.editions.strategy", c.Editions.Strategy, ServicingAuto, ServicingPerEdition, ServicingSharedBase),
		uniqueIdentifiers("conversion.editions.derived", c.Editions.Derived),
		enum("apps.mode", s.Apps.Mode, AppsDefault, AppsCustom, AppsNone),
		enum("apps.stub_policy", s.Apps.StubPolicy, AppStubAuto, AppStub, AppFull),
		enum("apps.edge_policy", s.Apps.Edge, EdgeDefault, EdgeInclude, EdgeExclude),
		uniqueIdentifiers("apps.include", s.Apps.Include),
		enum("output.kind", s.Output.Kind, OutputISO, OutputImage, OutputDirectory),
		enum("output.image_format", s.Output.ImageFormat, ImageWIM, ImageESD, ImageSWM),
		uniqueIdentifiers("output.edition_order", s.Output.EditionOrder),
		enum("downloads.proxy.mode", s.Downloads.Proxy.Mode, ProxySystem, ProxyDirect, ProxyExplicit),
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	if s.Apps.Preset != "" {
		if err := identifier("apps.preset", s.Apps.Preset); err != nil {
			return err
		}
	}
	if c.Drivers.Enabled && c.Drivers.Source == "" {
		return errors.New("conversion.drivers.source: required when integration is enabled")
	}
	if strings.ContainsRune(c.Drivers.Source, 0) {
		return errors.New("conversion.drivers.source: contains NUL")
	}
	if c.Drivers.Enabled && len(c.Drivers.Targets) == 0 {
		return errors.New("conversion.drivers.targets: at least one target is required")
	}
	seen := make(map[DriverTarget]bool)
	for _, target := range c.Drivers.Targets {
		if err := enum("conversion.drivers.targets", target, DriverOS, DriverWinPE, DriverWinRE, DriverShared); err != nil {
			return err
		}
		if seen[target] {
			return fmt.Errorf("conversion.drivers.targets: duplicate target %q", target)
		}
		seen[target] = true
	}
	if s.Output.SplitSizeMiB < 0 || (s.Output.ImageFormat == ImageSWM && s.Output.SplitSizeMiB == 0) {
		return errors.New("output.split_size_mib: must be positive for SWM and never negative")
	}
	for _, field := range []struct{ key, value string }{{"output.directory", s.Output.Directory}, {"output.filename", s.Output.Filename}, {"output.label", s.Output.Label}, {"storage.workspace", s.Storage.Workspace}, {"storage.cache", s.Storage.Cache}} {
		if err := identifier(field.key, field.value); err != nil {
			return err
		}
	}
	filename, err := ValidateRelativePath(s.Output.Filename)
	if err != nil || strings.Contains(filename, "/") {
		return errors.New("output.filename: must be auto or a single Windows-safe filename")
	}
	if s.Downloads.ParallelFiles <= 0 {
		return errors.New("downloads.parallel_files: must be positive")
	}
	if s.Downloads.Retries < 0 {
		return errors.New("downloads.retries: must not be negative")
	}
	p := s.Downloads.Proxy
	if p.Mode != ProxyExplicit && p.URL != "" {
		return errors.New("downloads.proxy.url: only valid with explicit mode")
	}
	if p.Mode == ProxyExplicit {
		u, err := url.Parse(p.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("downloads.proxy.url: expected an HTTP, HTTPS or SOCKS5 origin without credentials, query or fragment")
		}
	}
	return nil
}

func enum[T ~string](key string, value T, allowed ...T) error {
	for _, candidate := range allowed {
		if value == candidate {
			return nil
		}
	}
	return fmt.Errorf("%s: invalid value %q", key, value)
}

func uniqueIdentifiers(key string, values []string) error {
	seen := make(map[string]bool)
	for _, value := range values {
		if err := identifier(key, value); err != nil {
			return err
		}
		if seen[value] {
			return fmt.Errorf("%s: duplicate value %q", key, value)
		}
		seen[value] = true
	}
	return nil
}

type FileSystemCapabilities struct {
	Name             string `json:"name"`
	Local            bool   `json:"local"`
	ACLs             bool   `json:"acls"`
	AlternateStreams bool   `json:"alternate_streams"`
	ReparsePoints    bool   `json:"reparse_points"`
	HardLinks        bool   `json:"hard_links"`
}

type Host struct {
	WindowsBuild        uint32                 `json:"windows_build"`
	ProcessArchitecture Architecture           `json:"process_architecture"`
	NativeArchitecture  Architecture           `json:"native_architecture"`
	FileSystem          FileSystemCapabilities `json:"filesystem"`
}
