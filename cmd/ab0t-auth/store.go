package main

// store.go — profile-aware, multi-tenant credential and context storage.
//
// WHY THIS IS PROFILES AND NOT ONE FILE
//
// This SDK is the entry point for SaaS companies on the ab0t mesh, and the
// service is multi-tenant BY DEFAULT: a user belongs to many organizations
// (`/users/me/organizations`), organizations nest (`Organization.parent_id`),
// and a session can be moved between them (`/auth/switch-organization`).
//
// The previous layout was a single flat `auth.json` holding one token. That is a
// single-tenant store for a multi-tenant product, and the failure it produces is
// the quiet kind: an operator logs into staging, forgets, and runs a revoke
// against production an hour later. There is no wrong command in that sequence —
// only one identity where there should have been several.
//
// So: NAMED PROFILES, one file per tenant context, plus a pointer to the current
// one. This matches the house convention — `connect-cli` ships a `connect-auth`
// skill covering exactly "login, API keys, dev/prod, headless" — and it is the
// ordinary shape for multi-tenant tooling (aws profiles, kubectl contexts,
// gcloud configurations).
//
// LAYOUT
//
//	$XDG_CONFIG_HOME/ab0t/auth-sdk-go/        (0700)
//	  config.json                             (0600)  { "current_profile": "acme-prod" }
//	  profiles/                               (0700)
//	    acme-prod.json                        (0600)  one tenant context
//	    acme-dev.json                         (0600)
//
// Namespaced under a per-tool directory (`auth-sdk-go/`) rather than dumped at
// the root of `ab0t/`, so several ab0t tools can share the config root without
// colliding — the same reason the mesh's other clients do it.
//
// DATA-ENGINEERING PROPERTIES, deliberately
//
//   - One file per tenant. A profile can be copied, diffed, deleted or handed to
//     a colleague without touching any other tenant's state.
//   - Writes are atomic (temp + rename): an interrupted save cannot leave a
//     truncated file that then fails to parse on every subsequent run.
//   - 0600 inside 0700, re-asserted on every write — a directory created once
//     under a loose umask otherwise stays loose forever and nothing tells you.
//   - The token is the only secret; everything else (org, slug, store, service)
//     is context, and is what makes `whoami` able to answer "which tenant am I
//     in" rather than only "who am I".
//   - Legacy `auth.json` is imported as the profile `default` on first use, so
//     nobody is logged out by an upgrade.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const legacyFile = "auth.json"

// Credential is a resolved credential and where it came from. The source matters:
// "why is it using the wrong tenant" is a top support question and the answer is
// almost always an environment variable shadowing the selected profile.
type Credential struct {
	Value   string `json:"-"` // never serialised into output
	Source  string `json:"source"`
	Kind    string `json:"kind"`    // "api-key" or "token"
	Profile string `json:"profile"` // which tenant context this came from
}

func (c Credential) Present() bool { return c.Value != "" }

// Profile is one tenant context: a credential plus the tenancy it belongs to.
//
// OrgID/OrgSlug/Store are not decoration — they are what lets the tool say which
// company you are acting inside, which is the thing a single flat file could
// never answer.
type Profile struct {
	Name        string    `json:"name"`
	Token       string    `json:"token"`
	AuthService string    `json:"auth_service,omitempty"`
	OrgID       string    `json:"org_id,omitempty"`
	OrgSlug     string    `json:"org_slug,omitempty"`
	Store       string    `json:"store,omitempty"`
	Email       string    `json:"email,omitempty"`
	SavedAt     time.Time `json:"saved_at"`
}

type rootConfig struct {
	CurrentProfile string `json:"current_profile"`
}

// ---- paths ----

func configDir() string {
	if v := os.Getenv("AB0T_CONFIG_DIR"); v != "" {
		return v
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "ab0t", "auth-sdk-go")
	}
	return filepath.Join(dir, "ab0t", "auth-sdk-go")
}

func profilesDir() string         { return filepath.Join(configDir(), "profiles") }
func profilePath(n string) string { return filepath.Join(profilesDir(), sanitizeProfile(n)+".json") }
func rootConfigPath() string      { return filepath.Join(configDir(), "config.json") }
func legacyPath() string          { return filepath.Join(configDir(), legacyFile) }

// sanitizeProfile keeps a profile name safe as a filename. A tenant slug comes
// from outside, so it must never be able to escape the profiles directory.
func sanitizeProfile(n string) string {
	if n == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		return "default"
	}
	return s
}

func kindOf(cred string) string {
	if strings.HasPrefix(cred, "ab0t_sk_") {
		return "api-key"
	}
	return "token"
}

// ---- profile selection ----

// CurrentProfileName resolves which tenant context is active.
//
// Precedence: --profile > $AB0T_PROFILE > config.json > "default", then the
// ENVIRONMENT is appended if one is selected.
//
// Environment is a first-class axis because the house tool (`authsetup`, from
// ab0t-com/clientsetup) makes it one: it isolates credentials per environment as
// `<svc>.<env>.json` while the config stays shared, so "the same config promotes
// dev to prod". The reason that exists is the reason we copy it — it is what
// stops a dev credential being used against production. A profile named "acme"
// with --env prod resolves to "acme.prod", stored separately from "acme.dev".
func CurrentProfileName(flagVal string) string {
	return withEnv(baseProfileName(flagVal), os.Getenv("AB0T_ENV"))
}

// CurrentProfileNameEnv is CurrentProfileName with an explicit --env value,
// which takes precedence over $AB0T_ENV.
func CurrentProfileNameEnv(flagVal, envFlag string) string {
	env := envFlag
	if env == "" {
		env = os.Getenv("AB0T_ENV")
	}
	return withEnv(baseProfileName(flagVal), env)
}

func baseProfileName(flagVal string) string {
	if flagVal != "" {
		return sanitizeProfile(flagVal)
	}
	if v := os.Getenv("AB0T_PROFILE"); v != "" {
		return sanitizeProfile(v)
	}
	if b, err := os.ReadFile(rootConfigPath()); err == nil {
		var rc rootConfig
		if json.Unmarshal(b, &rc) == nil && rc.CurrentProfile != "" {
			return sanitizeProfile(rc.CurrentProfile)
		}
	}
	return "default"
}

// withEnv appends the environment segment. Kept as a dot-joined suffix rather
// than a nested directory so a profile and its environments sort together in a
// listing — the same reason authsetup keeps <svc>.<env>.json in one flat dir.
func withEnv(base, env string) string {
	if env == "" {
		return base
	}
	return base + "." + sanitizeProfile(env)
}

// SetCurrentProfile records the active tenant context.
func SetCurrentProfile(name string) error {
	if err := ensureDirs(); err != nil {
		return err
	}
	return writeAtomic(rootConfigPath(), mustJSON(rootConfig{CurrentProfile: sanitizeProfile(name)}))
}

// ListProfiles returns every stored tenant context, sorted.
func ListProfiles() ([]Profile, error) {
	migrateLegacy()
	entries, err := os.ReadDir(profilesDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Profile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if p, err := LoadProfile(strings.TrimSuffix(e.Name(), ".json")); err == nil {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func LoadProfile(name string) (*Profile, error) {
	migrateLegacy()
	b, err := os.ReadFile(profilePath(name))
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON (delete it and log in again): %w", profilePath(name), err)
	}
	if p.Name == "" {
		p.Name = sanitizeProfile(name)
	}
	return &p, nil
}

func SaveProfile(p *Profile) error {
	if err := ensureDirs(); err != nil {
		return err
	}
	p.Name = sanitizeProfile(p.Name)
	p.SavedAt = time.Now().UTC()
	return writeAtomic(profilePath(p.Name), mustJSON(p))
}

func DeleteProfile(name string) (bool, error) {
	err := os.Remove(profilePath(name))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// ---- credential resolution ----

// resolveCredential applies the precedence chain. Order is the contract: an
// explicit flag always wins, then the environment, then the selected profile.
// Anything else would make a one-off override impossible.
func resolveCredential(flagVal, profileFlag, envFlag string) Credential {
	if flagVal != "" {
		return Credential{Value: flagVal, Source: "--token", Kind: kindOf(flagVal), Profile: "(flag)"}
	}
	for _, env := range []string{"AB0T_AUTH_TOKEN", "AUTH_SERVICE_KEY"} {
		if v := os.Getenv(env); v != "" {
			return Credential{Value: v, Source: "$" + env, Kind: kindOf(v), Profile: "(env)"}
		}
	}
	name := CurrentProfileNameEnv(profileFlag, envFlag)
	if p, err := LoadProfile(name); err == nil && p.Token != "" {
		return Credential{Value: p.Token, Source: profilePath(name), Kind: kindOf(p.Token), Profile: p.Name}
	}
	return Credential{Profile: name}
}

// ---- io helpers ----

func ensureDirs() error {
	for _, d := range []string{configDir(), profilesDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		// MkdirAll is a no-op on an existing directory, so a dir created earlier
		// under a loose umask would otherwise stay loose.
		if err := os.Chmod(d, 0o700); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return append(b, '\n')
}

// writeAtomic writes via a temp file and rename, so an interrupted save cannot
// leave a truncated credential file that fails to parse forever after.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// migrateLegacy imports a pre-profiles auth.json as the "default" profile, so an
// upgrade never silently logs anyone out. Runs at most once — the legacy file is
// renamed aside rather than deleted, because destroying a credential during an
// upgrade is not a recoverable mistake.
func migrateLegacy() {
	b, err := os.ReadFile(legacyPath())
	if err != nil {
		return
	}
	var old struct {
		Token       string `json:"token"`
		AuthService string `json:"auth_service"`
		OrgID       string `json:"org_id"`
		Email       string `json:"email"`
	}
	if json.Unmarshal(b, &old) != nil || old.Token == "" {
		return
	}
	if _, err := os.Stat(profilePath("default")); err == nil {
		return // already migrated
	}
	_ = SaveProfile(&Profile{
		Name: "default", Token: old.Token, AuthService: old.AuthService,
		OrgID: old.OrgID, Email: old.Email,
	})
	_ = os.Rename(legacyPath(), legacyPath()+".migrated")
}

// checkPerms reports a credential file readable by anyone else. Worth saying out
// loud rather than silently fixing: if the mode is wrong, something changed it.
func checkPerms() (string, bool) {
	name := CurrentProfileName("")
	st, err := os.Stat(profilePath(name))
	if err != nil {
		return "", true
	}
	if m := st.Mode().Perm(); m&0o077 != 0 {
		return fmt.Sprintf("%s is mode %04o — readable by other users on this machine", profilePath(name), m), false
	}
	return "", true
}
