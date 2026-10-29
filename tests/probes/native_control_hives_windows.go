package probes

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"

	"uupbuilder/internal/registryhive"
)

// The default-user Preload target is a frozen independent verification
// hypothesis for this recipe. DISM documents input-profile intent, not this
// complete registry layout. DEFAULT remains an observation, not an assumed
// input-setting change. UI/system/user locale and image identity must persist.
type controlObservation struct {
	UserPreload, DefaultPreload                                            string
	UserSubstitutes, DefaultSubstitutes                                    map[string]string
	UserLocale, DefaultLocale, UserLocaleHex, DefaultLocaleHex             string
	SystemCurrent                                                          uint32
	SystemInstall, SystemDefault                                           string
	Edition, ProductName, Installation, Build, BuildNumber, DisplayVersion string
	UBR                                                                    uint32
	EnglishUI                                                              bool
	Hives                                                                  map[string]string
}

func controlBaselineObservation() controlObservation {
	return controlObservation{UserPreload: "00000409", DefaultPreload: "00000409", UserSubstitutes: map[string]string{}, DefaultSubstitutes: map[string]string{}, UserLocale: "en-US", DefaultLocale: "en-US", UserLocaleHex: "00000409", DefaultLocaleHex: "00000409", SystemCurrent: 1, SystemInstall: "0409", SystemDefault: "0409", Edition: "Professional", ProductName: "Windows 10 Enterprise", Installation: "Client", Build: "19045", BuildNumber: "19045", DisplayVersion: "22H2", UBR: 3803, EnglishUI: true}
}
func assertControlBaseline(b controlObservation) error {
	want := controlBaselineObservation()
	b.Hives = nil
	if !reflect.DeepEqual(b, want) {
		return errors.New("independent baseline hive values differ from frozen actual source")
	}
	return nil
}
func assertControlChange(b, a controlObservation, before, after controlPin) error {
	if err := assertControlBaseline(b); err != nil {
		return err
	}
	if before.SHA256 == "" || after.SHA256 == "" || before.SHA256 == after.SHA256 {
		return errors.New("actual before/after image bytes must change")
	}
	if a.UserPreload != "00000809" || len(a.UserSubstitutes) != 0 {
		return errors.New("durable default-user input target missing or substituted")
	}
	// DEFAULT input profile may change or remain unchanged; retain both raw
	// observations. This exemption does not relax user/identity/locale checks.
	a.UserPreload = b.UserPreload
	a.DefaultPreload = b.DefaultPreload
	a.DefaultSubstitutes = b.DefaultSubstitutes
	a.Hives = nil
	b.Hives = nil
	if !reflect.DeepEqual(a, b) {
		return errors.New("independent durable identity/UI/system/user-locale invariant changed")
	}
	return nil
}

var controlHiveMembers = map[string]string{"user": "Users/Default/NTUSER.DAT", "default": "Windows/System32/config/DEFAULT", "software": "Windows/System32/config/SOFTWARE", "system": "Windows/System32/config/SYSTEM"}
var controlSourceHives = map[string]struct{ File, SHA string }{
	"user":     {"member-14.bin", "35403b9bf20e35347a28fee9cb83925c47964b72472ebf9cf99731ee6bbab581"},
	"default":  {"member-15.bin", "e100818e5ec69f314b17d210e81a46f6b7b7a26e056c63b35ee97b8319a95f0b"},
	"software": {"member-16.bin", "a31e29e61f808e0021d3dac6645c7ee97e824d22a92ae0e182dcac543a0db914"},
	"system":   {"member-17.bin", "085582ae5243f42657ac5dd955ade9ae9aa451b989635d8e4db8a311056f64ac"},
}

func inspectControlHives(open func(string) (*os.File, error)) (o controlObservation, err error) {
	o.Hives = map[string]string{}
	for _, name := range []string{"user", "default", "software", "system"} {
		f, e := open(name)
		if e != nil {
			return o, e
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			return o, e
		}
		h, e := registryhive.Open(f, st.Size())
		if e != nil {
			f.Close()
			return o, e
		}
		// The same bounded object is hashed for observations; no source code or
		// host registry loader participates in independent inspection.
		if _, e = f.Seek(0, 0); e != nil {
			f.Close()
			return o, e
		}
		b := make([]byte, int(st.Size()))
		if _, e = f.ReadAt(b, 0); e != nil {
			f.Close()
			return o, e
		}
		sum := sha256.Sum256(b)
		o.Hives[name] = hex.EncodeToString(sum[:])
		f.Close()
		readString := func(path, key string) (string, error) {
			v, e := h.Value(path, key)
			if e != nil {
				return "", e
			}
			return v.String()
		}
		readDWORD := func(path, key string) (uint32, error) {
			v, e := h.Value(path, key)
			if e != nil {
				return 0, e
			}
			return v.DWORD()
		}
		if name == "user" || name == "default" {
			preload, e := h.Values(`Keyboard Layout\Preload`)
			if e != nil {
				return o, e
			}
			if len(preload) != 1 || preload[0].Name != "1" {
				return o, errors.New("prebound single default preload absent/ambiguous")
			}
			input, e := preload[0].String()
			if e != nil {
				return o, e
			}
			subs, e := h.Values(`Keyboard Layout\Substitutes`)
			if e != nil {
				return o, e
			}
			substitutes := map[string]string{}
			for _, v := range subs {
				s, e := v.String()
				if e != nil {
					return o, e
				}
				substitutes[v.Name] = s
			}
			locale, e := readString(`Control Panel\International`, "LocaleName")
			if e != nil {
				return o, e
			}
			localeHex, e := readString(`Control Panel\International`, "Locale")
			if e != nil {
				return o, e
			}
			if name == "user" {
				o.UserPreload = input
				o.UserSubstitutes = substitutes
				o.UserLocale = locale
				o.UserLocaleHex = localeHex
			} else {
				o.DefaultPreload = input
				o.DefaultSubstitutes = substitutes
				o.DefaultLocale = locale
				o.DefaultLocaleHex = localeHex
			}
		} else if name == "software" {
			path := `Microsoft\Windows NT\CurrentVersion`
			for key, dst := range map[string]*string{"EditionID": &o.Edition, "ProductName": &o.ProductName, "InstallationType": &o.Installation, "CurrentBuild": &o.Build, "CurrentBuildNumber": &o.BuildNumber, "DisplayVersion": &o.DisplayVersion} {
				*dst, e = readString(path, key)
				if e != nil {
					return o, e
				}
			}
			o.UBR, e = readDWORD(path, "UBR")
			if e != nil {
				return o, e
			}
		} else {
			o.SystemCurrent, e = readDWORD(`Select`, "Current")
			if e != nil {
				return o, e
			}
			if o.SystemCurrent != 1 {
				return o, errors.New("unreviewed source control set")
			}
			o.SystemInstall, e = readString(`ControlSet001\Control\Nls\Language`, "InstallLanguage")
			if e != nil {
				return o, e
			}
			o.SystemDefault, e = readString(`ControlSet001\Control\Nls\Language`, "Default")
			if e != nil {
				return o, e
			}
			_, e = h.Values(`ControlSet001\Control\MUI\UILanguages\en-US`)
			if e != nil {
				return o, fmt.Errorf("English UI hive key: %w", e)
			}
			o.EnglishUI = true
		}
	}
	return o, nil
}
