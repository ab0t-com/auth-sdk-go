package main

// store.go — credential storage.
//
// Follows the house pattern set by the `lc` CLI (see the ticket's
// evidence/house_cli_inventory.txt): a JSON file at mode 0600 inside a 0700
// directory, resolved through a flag -> environment -> file precedence chain.
//
// Two departures, both deliberate:
//
//   - the path is org-neutral and XDG-aware (os.UserConfigDir, so
//     ~/.config/ab0t/auth.json and the right thing on macOS/Windows), because
//     this CLI belongs to the auth service, not to one product that uses it;
//   - the file is re-chmodded to 0600 on every write even when it already
//     existed, because a file created once with a loose umask stays loose
//     forever otherwise, and nothing would ever tell you.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Credential is a resolved credential and where it came from. The source matters:
// "why is it using the wrong token" is a top support question, and the answer is
// almost always that an environment variable is shadowing the stored one.
type Credential struct {
	Value  string `json:"-"` // never serialised into output
	Source string `json:"source"`
	Kind   string `json:"kind"` // "api-key" or "token"
}

func (c Credential) Present() bool { return c.Value != "" }

// storedFile is what lands on disk. The token is stored in plain text at 0600,
// matching the house CLI. That is a deliberate, stated trade-off rather than an
// oversight: an OS keyring would need a dependency in a module whose defining
// property is having none, and 0600 is the same protection every other CLI in
// this org gives the same class of secret.
type storedFile struct {
	Token       string    `json:"token"`
	AuthService string    `json:"auth_service,omitempty"`
	OrgID       string    `json:"org_id,omitempty"`
	Email       string    `json:"email,omitempty"`
	SavedAt     time.Time `json:"saved_at"`
}

func configDir() string {
	if v := os.Getenv("AB0T_CONFIG_DIR"); v != "" {
		return v
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "ab0t")
	}
	return filepath.Join(dir, "ab0t")
}

func credPath() string { return filepath.Join(configDir(), "auth.json") }

func kindOf(cred string) string {
	if len(cred) >= 8 && cred[:8] == "ab0t_sk_" {
		return "api-key"
	}
	return "token"
}

// resolveCredential applies the precedence chain. Order is the contract:
// an explicit flag always wins, then the environment, then the stored file.
// Anything else would make a one-off override impossible.
func resolveCredential(flagVal string) Credential {
	if flagVal != "" {
		return Credential{Value: flagVal, Source: "--token", Kind: kindOf(flagVal)}
	}
	for _, env := range []string{"AB0T_AUTH_TOKEN", "AUTH_SERVICE_KEY"} {
		if v := os.Getenv(env); v != "" {
			return Credential{Value: v, Source: "$" + env, Kind: kindOf(v)}
		}
	}
	if f, err := loadCredential(); err == nil && f.Token != "" {
		return Credential{Value: f.Token, Source: credPath(), Kind: kindOf(f.Token)}
	}
	return Credential{}
}

func loadCredential() (*storedFile, error) {
	b, err := os.ReadFile(credPath())
	if err != nil {
		return nil, err
	}
	var f storedFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON (delete it and log in again): %w", credPath(), err)
	}
	return &f, nil
}

// saveCredential writes the file with restrictive permissions.
//
// The write is atomic (temp file + rename) so an interrupted save cannot leave a
// truncated credential file that then fails to parse on every subsequent run.
func saveCredential(f *storedFile) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Re-assert directory perms: MkdirAll is a no-op on an existing directory, so
	// a dir created earlier with a loose umask would otherwise stay loose.
	if err := os.Chmod(dir, 0o700); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	f.SavedAt = time.Now().UTC()
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "auth-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, credPath()); err != nil {
		return err
	}
	// Belt and braces: enforce 0600 even if the destination pre-existed.
	return os.Chmod(credPath(), 0o600)
}

func deleteCredential() (bool, error) {
	err := os.Remove(credPath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// checkPerms reports a credential file that is readable by anyone else. Worth
// saying out loud rather than silently fixing: if the mode is wrong, something
// changed it, and the user should know.
func checkPerms() (string, bool) {
	st, err := os.Stat(credPath())
	if err != nil {
		return "", true
	}
	if m := st.Mode().Perm(); m&0o077 != 0 {
		return fmt.Sprintf("%s is mode %04o — it is readable by other users on this machine", credPath(), m), false
	}
	return "", true
}
