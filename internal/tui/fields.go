package tui

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
)

// settingField binds the editor directly to a public typed setting. Values
// remain requested values; applicability never writes through these bindings.
type settingField struct {
	key, group, label, value string
	choices                  []string // values offered by the UI; write can retain legacy schema values
	read                     func(config.Config) string
	write                    func(*config.Config, string) error
}

func stringField[T ~string](key, group, label string, access func(*config.Config) *T, choices ...T) settingField {
	f := settingField{key: key, group: group, label: label}
	for _, choice := range choices {
		f.choices = append(f.choices, string(choice))
	}
	f.read = func(cfg config.Config) string { return string(*access(&cfg)) }
	f.write = func(cfg *config.Config, value string) error {
		if len(choices) > 0 && !slices.Contains(choices, T(value)) {
			return fmt.Errorf("%s: choose %s", key, strings.Join(f.choices, ", "))
		}
		*access(cfg) = T(value)
		return nil
	}
	return f
}
func boolField(key, group, label string, access func(*config.Config) *bool) settingField {
	return settingField{key: key, group: group, label: label, choices: []string{"false", "true"},
		read: func(cfg config.Config) string { return strconv.FormatBool(*access(&cfg)) },
		write: func(cfg *config.Config, value string) error {
			if value != "true" && value != "false" {
				return fmt.Errorf("%s: expected true or false", key)
			}
			*access(cfg) = value == "true"
			return nil
		},
	}
}
func intField(key, group, label string, access func(*config.Config) *int) settingField {
	return settingField{key: key, group: group, label: label,
		read: func(cfg config.Config) string { return strconv.Itoa(*access(&cfg)) },
		write: func(cfg *config.Config, value string) error {
			n, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("%s: expected an integer", key)
			}
			*access(cfg) = n
			return nil
		},
	}
}
func listField[T ~string](key, group, label string, access func(*config.Config) *[]T, choices ...T) settingField {
	return settingField{key: key, group: group, label: label,
		read: func(cfg config.Config) string {
			var values []string
			for _, value := range *access(&cfg) {
				values = append(values, string(value))
			}
			return strings.Join(values, ", ")
		},
		write: func(cfg *config.Config, value string) error {
			values := []T{}
			if strings.TrimSpace(value) != "" {
				for _, part := range strings.Split(value, ",") {
					item := T(strings.TrimSpace(part))
					if len(choices) > 0 && !slices.Contains(choices, item) {
						return fmt.Errorf("%s: unknown target %q; use os, winpe, winre, shared", key, item)
					}
					values = append(values, item)
				}
			}
			*access(cfg) = values
			return nil
		},
	}
}

func conversionFields() []settingField {
	// Parsing retains every schema-1 value. Activating this control explicitly
	// chooses the current deliverable, including when a legacy value was loaded.
	outputKind := stringField("output.kind", "ISO output", "Output kind (ISO only)", func(c *config.Config) *model.OutputKind { return &c.Output.Kind }, model.OutputISO, model.OutputImage, model.OutputDirectory)
	outputKind.choices = []string{string(model.OutputISO)}
	return []settingField{
		stringField("conversion.updates", "Updates", "Update handling", func(c *config.Config) *model.UpdatePolicy { return &c.Conversion.Updates }, model.UpdatesIntegrate, model.UpdatesExternal, model.UpdatesOmit),
		stringField("conversion.servicing_strategy", "Updates", "Servicing strategy", func(c *config.Config) *model.ServicingStrategy { return &c.Conversion.ServicingStrategy }, model.ServicingAuto, model.ServicingPerEdition, model.ServicingSharedBase),
		stringField("conversion.cumulative_update_policy", "Updates", "Cumulative updates", func(c *config.Config) *model.ExpansionPolicy { return &c.Conversion.CumulativeUpdates }, model.ExpansionAuto, model.ExpansionExpand, model.ExpansionPreserve),
		stringField("conversion.checkpoint_updates", "Updates", "Checkpoint updates", func(c *config.Config) *model.ExpansionPolicy { return &c.Conversion.CheckpointUpdates }, model.ExpansionAuto, model.ExpansionExpand, model.ExpansionPreserve),
		stringField("conversion.enablement_packages", "Updates", "Enablement packages", func(c *config.Config) *model.InclusionPolicy { return &c.Conversion.EnablementPackages }, model.InclusionAuto, model.InclusionInclude, model.InclusionOmit),
		boolField("conversion.cleanup", "Updates", "Component cleanup", func(c *config.Config) *bool { return &c.Conversion.Cleanup }),
		stringField("conversion.reset_base", "Updates", "Reset component base", func(c *config.Config) *model.ResetBasePolicy { return &c.Conversion.ResetBase }, model.ResetBaseOff, model.ResetBaseAuto, model.ResetBaseOn),
		stringField("conversion.cumulative_msu", "Updates", "Cumulative MSU", func(c *config.Config) *model.MSUPolicy { return &c.Conversion.CumulativeMSU }, model.MSUAuto, model.MSUExpand, model.MSUKeep),
		stringField("conversion.reference_images", "Updates", "Reference images", func(c *config.Config) *model.ReferenceImagePolicy { return &c.Conversion.ReferenceImages }, model.ReferenceAuto, model.ReferenceReuse, model.ReferenceExport),
		boolField("conversion.keep_reference_esds", "Updates", "Keep reference ESDs", func(c *config.Config) *bool { return &c.Conversion.KeepReferenceESDs }),
		listField("conversion.editions.derived", "Editions", "Derived editions (comma separated)", func(c *config.Config) *[]string { return &c.Conversion.Editions.Derived }),
		stringField("conversion.editions.strategy", "Editions", "Edition servicing", func(c *config.Config) *model.ServicingStrategy { return &c.Conversion.Editions.Strategy }, model.ServicingAuto, model.ServicingPerEdition, model.ServicingSharedBase),
		boolField("conversion.editions.preserve_required_bases", "Editions", "Preserve temporary required bases", func(c *config.Config) *bool { return &c.Conversion.Editions.PreserveRequiredBases }),
		boolField("conversion.netfx3", "Features", ".NET Framework 3", func(c *config.Config) *bool { return &c.Conversion.NetFX3 }),
		boolField("conversion.include_winre", "Excluded recovery", "Include WinRE (legacy)", func(c *config.Config) *bool { return &c.Conversion.IncludeWinRE }),
		stringField("conversion.winre_updates", "Excluded recovery", "WinRE updates (legacy)", func(c *config.Config) *model.InclusionPolicy { return &c.Conversion.WinREUpdates }, model.InclusionAuto, model.InclusionInclude, model.InclusionOmit),
		boolField("conversion.update_boot_files", "ISO contents", "Update boot files", func(c *config.Config) *bool { return &c.Conversion.UpdateBootFiles }),
		stringField("conversion.boot_wim_engine", "ISO contents", "Boot WIM engine", func(c *config.Config) *model.BootWIMEngine { return &c.Conversion.BootWIMEngine }, model.BootWIMAuto, model.BootWIMWimlib, model.BootWIMDISM),
		boolField("conversion.drivers.enabled", "Drivers", "Integrate drivers", func(c *config.Config) *bool { return &c.Conversion.Drivers.Enabled }),
		stringField("conversion.drivers.source", "Drivers", "Driver source directory", func(c *config.Config) *string { return &c.Conversion.Drivers.Source }),
		listField("conversion.drivers.targets", "Drivers", "Targets (WinRE excluded)", func(c *config.Config) *[]model.DriverTarget { return &c.Conversion.Drivers.Targets }, model.DriverOS, model.DriverWinPE, model.DriverWinRE, model.DriverShared),
		outputKind,
		stringField("output.image_format", "ISO output", "Image inside ISO", func(c *config.Config) *model.ImageFormat { return &c.Output.ImageFormat }, model.ImageWIM, model.ImageESD, model.ImageSWM),
		intField("output.split_size_mib", "ISO output", "SWM split size (MiB)", func(c *config.Config) *int { return &c.Output.SplitSizeMiB }),
		stringField("output.directory", "ISO output", "Output directory", func(c *config.Config) *string { return &c.Output.Directory }),
		stringField("output.filename", "ISO output", "Filename (auto or name)", func(c *config.Config) *string { return &c.Output.Filename }),
		stringField("output.label", "ISO output", "Volume label (auto or label)", func(c *config.Config) *string { return &c.Output.Label }),
		listField("output.edition_order", "ISO output", "Edition order (comma separated)", func(c *config.Config) *[]string { return &c.Output.EditionOrder }),
		stringField("downloads.proxy.mode", "Downloads", "Proxy mode", func(c *config.Config) *model.ProxyMode { return &c.Downloads.Proxy.Mode }, model.ProxySystem, model.ProxyDirect, model.ProxyExplicit),
		stringField("downloads.proxy.url", "Downloads", "Proxy origin (no credentials)", func(c *config.Config) *string { return &c.Downloads.Proxy.URL }),
		intField("downloads.parallel_files", "Downloads", "Parallel files", func(c *config.Config) *int { return &c.Downloads.ParallelFiles }),
		intField("downloads.retries", "Downloads", "Retries", func(c *config.Config) *int { return &c.Downloads.Retries }),
		stringField("storage.workspace", "Storage", "Scratch workspace (auto or path)", func(c *config.Config) *string { return &c.Storage.Workspace }),
		stringField("storage.cache", "Storage", "Download cache (auto or path)", func(c *config.Config) *string { return &c.Storage.Cache }),
		boolField("storage.keep_downloads", "Storage", "Keep downloads", func(c *config.Config) *bool { return &c.Storage.KeepDownloads }),
		boolField("storage.keep_intermediates", "Storage", "Keep intermediates", func(c *config.Config) *bool { return &c.Storage.KeepIntermediates }),
	}
}
