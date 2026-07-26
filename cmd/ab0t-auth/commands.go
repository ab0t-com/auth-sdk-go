package main

// commands.go — the subcommands.
//
// Each one is a JOB someone actually has, not an endpoint. `can` answers "may
// alice do this", which is three SDK calls' worth of ceremony; `doctor` answers
// "why isn't it working", which is otherwise a support ticket.
//
// Every command that prints anything supports --json with the same facts as the
// text output. If a field appears in only one of them, whoever picked the other
// mode is getting a worse answer.

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	auth "github.com/ab0t-com/auth-sdk-go"
	"time"
)

// loginOpts are `login`'s own flags.
type loginOpts struct{ email, password, org, key string }

func loginFlags(fs *flag.FlagSet) any {
	o := &loginOpts{}
	fs.StringVar(&o.email, "email", "", "Email address to log in with")
	fs.StringVar(&o.password, "password", "", "Password; prompted for if omitted and stdin is a terminal")
	fs.StringVar(&o.org, "org", "", "Organization id to log in to")
	fs.StringVar(&o.key, "key", "", "Store a service API key (ab0t_sk_…) instead of logging in")
	return o
}

// storeOpts is shared by the Zanzibar commands.
type storeOpts struct {
	store string
	// dryRun prints what a write WOULD do and sends nothing.
	//
	// Journey UJ-E06: every evaluator invented their own safe path (a throwaway
	// store) because the tool offered none. A write verb with no rehearsal is a
	// write verb people are afraid of, and fear reads as "this tool is dangerous".
	dryRun bool
	// expires time-boxes a grant. UJ-P07: support engineers grant permanent access
	// for a temporary need because the CLI offered no expiry, even though the
	// service supports it. That is a permissions leak created by our own UI.
	expires string
}

func storeFlags(fs *flag.FlagSet) any {
	o := &storeOpts{}
	fs.StringVar(&o.store, "store", os.Getenv("AB0T_ZANZIBAR_STORE"), "Zanzibar store id (or $AB0T_ZANZIBAR_STORE)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "Show what would change and send nothing")
	fs.StringVar(&o.expires, "expires", "", "Time-box a grant, e.g. 24h or 2026-08-01T00:00:00Z")
	return o
}

// yesOpts guards a destructive action.
type yesOpts struct{ yes bool }

func yesFlags(fs *flag.FlagSet) any {
	o := &yesOpts{}
	fs.BoolVar(&o.yes, "yes", false, "Do not ask for confirmation")
	fs.BoolVar(&o.yes, "y", false, "Do not ask for confirmation (shorthand)")
	return o
}

var commands = []command{
	{"login", "Authenticate and store a credential", "login [--email E] [--password P] [--org ORG] | login --key ab0t_sk_…", loginFlags, cmdLogin},
	{"logout", "Remove the stored credential", "logout [--yes]", yesFlags, cmdLogout},
	{"whoami", "Show the identity behind the current credential", "whoami", nil, cmdWhoami},
	{"can", "Ask whether a subject may act on an object", "can <subject> <permission> <object> --store STORE", storeFlags, cmdCan},
	{"why", "Explain an authorization decision", "why <subject> <permission> <object> --store STORE", storeFlags, cmdWhy},
	{"who-can", "List subjects that may act on an object", "who-can <object> <permission> --store STORE", storeFlags, cmdWhoCan},
	{"what-can", "List objects a subject may act on", "what-can <subject> <permission> <object-type> --store STORE", storeFlags, cmdWhatCan},
	{"grant", "Write a relationship tuple", "grant <subject> <relation> <object> --store STORE", storeFlags, cmdGrant},
	{"revoke", "Remove a relationship tuple", "revoke <subject> <relation> <object> --store STORE", storeFlags, cmdRevoke},
	{"revoke-all", "Remove every relationship on an object (offboarding)", "revoke-all <object> --store STORE [--dry-run]", storeFlags, cmdRevokeAll},
	{"profile", "List, switch and remove tenant profiles", "profile [list|use <name>|remove <name>]", nil, cmdProfile},
	{"orgs", "List the organizations this credential belongs to", "orgs", nil, cmdOrgs},
	{"org-tree", "Show an organization's hierarchy: sub-orgs, teams, users", "org-tree <org-id>", nil, cmdOrgTree},
	{"about", "Licence, support, source and the Go SDK", "about", nil, cmdAbout},
	{"health", "Check that the auth service is reachable and healthy", "health", nil, cmdHealth},
	{"doctor", "Diagnose configuration and connectivity", "doctor", nil, cmdDoctor},
}

func needStore(store string) error {
	if store == "" {
		return errors.New("a store is required: pass --store STORE or set $AB0T_ZANZIBAR_STORE")
	}
	return nil
}

func needArgs(args []string, n int, form string) error {
	if len(args) < n {
		return fmt.Errorf("expected %d arguments: %s", n, form)
	}
	return nil
}

// ---- credentials ----

func cmdLogin(ctx context.Context, e *env, opts any, args []string) error {
	o := opts.(*loginOpts)
	email, password, org, key := o.email, o.password, o.org, o.key

	// An API key needs no round trip to store, but validating it now means the
	// user finds out here rather than on their next command.
	if key != "" {
		res, err := e.client().ValidateAPIKey(ctx, auth.ValidateAPIKeyRequest{APIKey: key})
		if err != nil {
			return fmt.Errorf("could not validate the key: %w", err)
		}
		if !res.Valid {
			return fmt.Errorf("the auth service rejected that key: %s", res.Reason)
		}
		if err := SaveProfile(&Profile{Name: e.profileName(), Token: key, AuthService: e.g.server, OrgID: res.OrgID}); err != nil {
			return err
		}
		return e.out.emit(map[string]any{"saved": true, "kind": "api-key", "path": profilePath(e.profileName()), "org_id": res.OrgID},
			func() { e.out.ok("stored API key " + mask(key) + " in " + profilePath(e.profileName())) })
	}

	if email == "" {
		return errors.New("--email is required (or use --key ab0t_sk_… for a service key)")
	}
	if password == "" {
		// Prompting is fine, but it must never be the ONLY way: --password and
		// --key both work non-interactively, so this is reachable from a script.
		if !isTerminal(os.Stdin) {
			return errors.New("--password is required when stdin is not a terminal")
		}
		fmt.Fprint(os.Stderr, "Password: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr)
		password = strings.TrimSpace(line)
	}

	ts, err := e.client().Login(ctx, auth.LoginRequest{Email: email, Password: password, OrgID: org})
	if err != nil {
		return err
	}
	if ts.AccessToken == "" {
		return errors.New("the auth service returned no access token")
	}
	if err := SaveProfile(&Profile{Name: e.profileName(), Token: ts.AccessToken, AuthService: e.g.server, OrgID: org, Email: email}); err != nil {
		return err
	}
	return e.out.emit(map[string]any{"saved": true, "kind": "token", "path": profilePath(e.profileName()), "email": email},
		func() { e.out.ok("logged in as " + email + "; credential stored in " + profilePath(e.profileName())) })
}

func cmdLogout(_ context.Context, e *env, opts any, _ []string) error {
	// Destructive actions confirm — but only when a human is there to answer.
	// A prompt that blocks in CI is a hang, not a safeguard, so a non-TTY stdin
	// proceeds and --yes/-y is always available.
	if !opts.(*yesOpts).yes && isTerminal(os.Stdin) && !e.g.quiet {
		fmt.Fprintf(os.Stderr, "Remove the stored credential at %s? Type 'yes' to confirm: ", profilePath(e.profileName()))
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			return errors.New("cancelled")
		}
	}
	removed, err := DeleteProfile(e.profileName())
	if err != nil {
		return err
	}
	return e.out.emit(map[string]any{"removed": removed, "path": profilePath(e.profileName())}, func() {
		if removed {
			e.out.ok("removed " + profilePath(e.profileName()))
			return
		}
		e.out.printf("no stored credential at %s\n", profilePath(e.profileName()))
	})
}

func cmdWhoami(ctx context.Context, e *env, opts any, _ []string) error {
	if !e.cred.Present() {
		return errNoCredential
	}
	actor, err := e.client().ValidateToken(ctx, e.cred.Value)
	if err != nil {
		return err
	}
	if actor == nil || !actor.Valid {
		reason := "the auth service rejected it"
		if actor != nil && actor.Error != "" {
			reason = actor.Error
		}
		return fmt.Errorf("credential is not valid: %s: %w", reason, errNoCredential)
	}
	return e.out.emit(actor, func() {
		e.out.kv(
			[2]string{"user", actor.UserID},
			[2]string{"org", actor.OrgID},
			[2]string{"email", actor.Email},
			[2]string{"credential", mask(e.cred.Value) + " (" + e.cred.Kind + ")"},
			[2]string{"profile", e.cred.Profile},
			[2]string{"source", e.cred.Source},
		)
		if len(actor.Permissions) > 0 {
			e.out.printf("permissions:\n")
			e.out.list(actor.Permissions)
		}
	})
}

// ---- zanzibar ----

func cmdCan(ctx context.Context, e *env, opts any, args []string) error {
	store, rest := opts.(*storeOpts).store, args
	if err := needStore(store); err != nil {
		return err
	}
	if err := needArgs(rest, 3, "can <subject> <permission> <object>"); err != nil {
		return err
	}
	if !e.cred.Present() {
		return errNoCredential
	}

	res, err := e.client().Store(store, e.cred.Value).Why(ctx, rest[0], rest[1], rest[2])
	if err != nil {
		return err
	}
	err = e.out.emit(res, func() {
		e.out.printf("%s  %s %s %s\n", e.out.verdict(res.Allowed), rest[0], rest[1], rest[2])
		if res.Reason != "" {
			e.out.printf("  reason: %s\n", res.Reason)
		}
	})
	if err != nil {
		return err
	}
	// Exit code carries the answer so `if ab0t-auth can …; then` works.
	if !res.Allowed {
		return errDenied
	}
	return nil
}

func cmdWhy(ctx context.Context, e *env, opts any, args []string) error {
	store, rest := opts.(*storeOpts).store, args
	if err := needStore(store); err != nil {
		return err
	}
	if err := needArgs(rest, 3, "why <subject> <permission> <object>"); err != nil {
		return err
	}
	if !e.cred.Present() {
		return errNoCredential
	}
	res, err := e.client().Store(store, e.cred.Value).Why(ctx, rest[0], rest[1], rest[2])
	if err != nil {
		return err
	}
	return e.out.emit(res, func() {
		e.out.printf("%s  %s %s %s\n", e.out.verdict(res.Allowed), rest[0], rest[1], rest[2])
		if res.Reason != "" {
			e.out.printf("  reason: %s\n", res.Reason)
		}
		if len(res.Path) > 0 {
			e.out.printf("  path:   %s\n", strings.Join(res.Path, " -> "))
		}
		if res.Cached {
			e.out.printf("  cached: yes\n")
		}
	})
}

func cmdWhoCan(ctx context.Context, e *env, opts any, args []string) error {
	store, rest := opts.(*storeOpts).store, args
	if err := needStore(store); err != nil {
		return err
	}
	if err := needArgs(rest, 2, "who-can <object> <permission>"); err != nil {
		return err
	}
	if !e.cred.Present() {
		return errNoCredential
	}
	users, err := e.client().Store(store, e.cred.Value).WhoCan(ctx, rest[0], rest[1])
	if err != nil {
		return err
	}
	return e.out.emit(map[string]any{"object": rest[0], "permission": rest[1], "subjects": users, "count": len(users)},
		func() { e.out.list(users) })
}

func cmdWhatCan(ctx context.Context, e *env, opts any, args []string) error {
	store, rest := opts.(*storeOpts).store, args
	if err := needStore(store); err != nil {
		return err
	}
	if err := needArgs(rest, 3, "what-can <subject> <permission> <object-type>"); err != nil {
		return err
	}
	if !e.cred.Present() {
		return errNoCredential
	}
	objs, err := e.client().Store(store, e.cred.Value).WhatCan(ctx, rest[0], rest[1], rest[2])
	if err != nil {
		return err
	}
	return e.out.emit(map[string]any{"subject": rest[0], "permission": rest[1], "object_type": rest[2], "objects": objs, "count": len(objs)},
		func() { e.out.list(objs) })
}

func cmdGrant(ctx context.Context, e *env, opts any, args []string) error {
	return relate(ctx, e, opts, args, true)
}

func cmdRevoke(ctx context.Context, e *env, opts any, args []string) error {
	return relate(ctx, e, opts, args, false)
}

func relate(ctx context.Context, e *env, opts any, args []string, grant bool) error {
	verb := "revoke"
	if grant {
		verb = "grant"
	}
	store, rest := opts.(*storeOpts).store, args
	if err := needStore(store); err != nil {
		return err
	}
	if err := needArgs(rest, 3, verb+" <subject> <relation> <object>"); err != nil {
		return err
	}
	if !e.cred.Present() {
		return errNoCredential
	}
	so := opts.(*storeOpts)

	if so.dryRun {
		// Nothing is sent. Say so unmistakably: a dry run that looks like a real
		// run is worse than no dry run, because the operator believes the change
		// landed.
		return e.out.emit(map[string]any{
			"dry_run": true, "action": verb, "subject": rest[0],
			"relation": rest[1], "object": rest[2], "store": store,
		}, func() {
			e.out.printf("DRY RUN — nothing was sent\n")
			e.out.printf("  would %s: %s %s %s  (store %s)\n", verb, rest[0], rest[1], rest[2], store)
			if so.expires != "" {
				e.out.printf("  expiring: %s\n", so.expires)
			}
		})
	}

	st := e.client().Store(store, e.cred.Value)
	var err error
	if grant {
		if so.expires != "" {
			var exp time.Time
			exp, err = parseExpiry(so.expires)
			if err != nil {
				return err
			}
			err = st.RelateUntil(ctx, rest[0], rest[1], rest[2], exp)
		} else {
			err = st.RelateID(ctx, rest[0], rest[1], rest[2])
		}
	} else {
		err = st.UnrelateID(ctx, rest[0], rest[1], rest[2])
	}
	if err != nil {
		return err
	}
	return e.out.emit(map[string]any{"ok": true, "action": verb, "subject": rest[0], "relation": rest[1], "object": rest[2]},
		func() { e.out.ok(fmt.Sprintf("%sed %s %s %s", verb, rest[0], rest[1], rest[2])) })
}

// ---- diagnostics ----

func cmdHealth(ctx context.Context, e *env, opts any, _ []string) error {
	h, err := e.client().Health(ctx)
	if err != nil {
		return err
	}
	// Print the fields, not the struct. `fmt.Sprint` on a *HealthCheckResponse
	// rendered as "&{healthy  map[]}" — a Go pointer dump leaking into what is
	// supposed to be the friendliest command in the tool.
	status := h.Status
	if status == "" {
		status = "unknown"
	}
	pairs := [][2]string{{"status", status}}
	if h.Version != "" {
		pairs = append(pairs, [2]string{"version", h.Version})
	}
	return e.out.emit(h, func() { e.out.kv(pairs...) })
}

// cmdDoctor answers "why isn't it working" without a support ticket.
//
// It always exits 0 unless a check genuinely fails, and it reports EVERY check
// rather than stopping at the first problem — the second failure is often the
// one that explains the first.
func cmdDoctor(ctx context.Context, e *env, opts any, _ []string) error {
	type check struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	var checks []check
	add := func(name string, ok bool, detail string) { checks = append(checks, check{name, ok, detail}) }

	server := e.g.server
	if server == "" {
		server = auth.DefaultBaseURL
	}
	add("auth service URL", true, server)

	if e.cred.Present() {
		add("credential found", true, fmt.Sprintf("%s (%s) from %s", mask(e.cred.Value), e.cred.Kind, e.cred.Source))
	} else {
		add("credential found", false, "none — run 'ab0t-auth login', or set $AB0T_AUTH_TOKEN")
	}

	if msg, ok := checkPerms(); !ok {
		add("credential file permissions", false, msg)
	} else if e.cred.Source == profilePath(e.profileName()) {
		add("credential file permissions", true, "0600")
	}

	if _, err := e.client().Health(ctx); err != nil {
		add("service reachable", false, err.Error())
	} else {
		add("service reachable", true, "healthy")
	}

	if e.cred.Present() {
		actor, err := e.client().ValidateToken(ctx, e.cred.Value)
		switch {
		case err != nil:
			add("credential valid", false, err.Error())
		case actor == nil || !actor.Valid:
			add("credential valid", false, "the auth service rejected it — try 'ab0t-auth login'")
		default:
			add("credential valid", true, fmt.Sprintf("user=%s org=%s", actor.UserID, actor.OrgID))
		}
	}

	failed := 0
	for _, c := range checks {
		if !c.OK {
			failed++
		}
	}

	err := e.out.emit(map[string]any{"checks": checks, "failed": failed}, func() {
		for _, c := range checks {
			// The WORD carries the state; colour is decoration on top of it.
			mark := e.out.paint(ansiGreen, "PASS")
			if !c.OK {
				mark = e.out.paint(ansiRed, "FAIL")
			}
			e.out.printf("%s  %-28s %s\n", mark, c.Name, c.Detail)
		}
	})
	if err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(checks))
	}
	return nil
}

// parseExpiry accepts either a duration ("24h") or an RFC3339 instant. Both forms
// appear in the wild and guessing wrong about which one someone meant is worse
// than accepting both.
func parseExpiry(s string) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().UTC().Add(d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("could not read %q as an expiry: use a duration like 24h, or an RFC3339 time like 2026-08-01T00:00:00Z", s)
}

// cmdRevokeAll removes every relationship on an object.
//
// Journey UJ-S13: offboarding was a manual loop with no completeness guarantee —
// the reviewer had to already know every relation, and any they forgot stayed
// granted silently. "I think I removed everything" is not an answer a security
// reviewer can sign.
func cmdRevokeAll(ctx context.Context, e *env, opts any, args []string) error {
	so := opts.(*storeOpts)
	if err := needStore(so.store); err != nil {
		return err
	}
	if err := needArgs(args, 1, "revoke-all <object>"); err != nil {
		return err
	}
	if !e.cred.Present() {
		return errNoCredential
	}
	objType, objID, ok := strings.Cut(args[0], ":")
	if !ok || objType == "" || objID == "" {
		return fmt.Errorf("object must be a typed id like %q, got %q", "doc:123", args[0])
	}

	if so.dryRun {
		rels, err := e.client().Store(so.store, e.cred.Value).RelationsOn(ctx, objType, objID, "")
		if err != nil {
			return err
		}
		return e.out.emit(map[string]any{"dry_run": true, "object": args[0], "would_remove": len(rels), "relationships": rels},
			func() {
				e.out.printf("DRY RUN — nothing was sent\n")
				e.out.printf("  would remove %d relationship(s) on %s\n", len(rels), args[0])
				for _, r := range rels {
					e.out.printf("    %s %s\n", r.Relation, r.Subject)
				}
			})
	}

	n, err := e.client().DeleteAllRelationshipsForObject(ctx, so.store, objType, objID, e.cred.Value)
	if err != nil {
		return err
	}
	return e.out.emit(map[string]any{"ok": true, "object": args[0], "removed": n},
		func() { e.out.ok(fmt.Sprintf("removed %d relationship(s) on %s", n, args[0])) })
}

// cmdAbout surfaces the facts three different hats currently leave the tool to
// find: the licence (UJ-B05), where support lives (UJ-B04), and that this is a
// thin layer over an importable Go SDK (UJ-E11).
func cmdAbout(_ context.Context, e *env, _ any, _ []string) error {
	info := map[string]any{
		"name":         "ab0t-auth",
		"version":      auth.Version,
		"licence":      "MIT",
		"source":       "https://github.com/ab0t-com/auth-sdk-go",
		"issues":       "https://github.com/ab0t-com/auth-sdk-go/issues",
		"security":     "https://github.com/ab0t-com/auth-sdk-go/security/advisories/new",
		"changelog":    "https://github.com/ab0t-com/auth-sdk-go/blob/main/CHANGELOG.md",
		"go_sdk":       "go get github.com/ab0t-com/auth-sdk-go",
		"dependencies": 0,
		"service":      auth.DefaultBaseURL,
	}
	return e.out.emit(info, func() {
		e.out.kv(
			[2]string{"ab0t-auth", auth.Version},
			[2]string{"licence", "MIT"},
			[2]string{"source", "https://github.com/ab0t-com/auth-sdk-go"},
			[2]string{"issues", "https://github.com/ab0t-com/auth-sdk-go/issues"},
			[2]string{"security", "report privately — see SECURITY.md in the repo"},
			[2]string{"changelog", "https://github.com/ab0t-com/auth-sdk-go/blob/main/CHANGELOG.md"},
			[2]string{"go sdk", "go get github.com/ab0t-com/auth-sdk-go"},
			[2]string{"dependencies", "none — standard library only"},
			[2]string{"default service", auth.DefaultBaseURL},
		)
	})
}

// profileName is the tenant context this invocation is acting in.
func (e *env) profileName() string { return CurrentProfileName(e.g.profile) }

// ---- tenancy ----
//
// The service is multi-tenant by default: a user belongs to many organizations,
// organizations nest via parent_id, and a session can be switched between them.
// The CLI exposed none of that, so an operator had one identity for a product
// with many — which is how a staging credential ends up running against
// production without a single wrong command being typed.

func cmdProfile(_ context.Context, e *env, _ any, args []string) error {
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		profs, err := ListProfiles()
		if err != nil {
			return err
		}
		cur := e.profileName()
		type row struct {
			Name    string `json:"name"`
			Current bool   `json:"current"`
			Org     string `json:"org_id,omitempty"`
			Slug    string `json:"org_slug,omitempty"`
			Service string `json:"auth_service,omitempty"`
			Email   string `json:"email,omitempty"`
		}
		out := []row{}
		for _, p := range profs {
			out = append(out, row{p.Name, p.Name == cur, p.OrgID, p.OrgSlug, p.AuthService, p.Email})
		}
		return e.out.emit(map[string]any{"current": cur, "profiles": out}, func() {
			if len(out) == 0 {
				e.out.printf("no profiles yet — run 'ab0t-auth login' to create one\n")
				return
			}
			for _, r := range out {
				mark := "  "
				if r.Current {
					// A word, not only a colour: the active tenant must be
					// unmistakable when piped, logged or read aloud.
					mark = "* "
				}
				e.out.printf("%s%-20s %s %s\n", mark, r.Name, r.Org, r.Email)
			}
			e.out.printf("\n* = current\n")
		})

	case "use":
		if len(args) < 2 {
			return errors.New("usage: ab0t-auth profile use <name>")
		}
		if _, err := LoadProfile(args[1]); err != nil {
			return fmt.Errorf("no profile named %q — run 'ab0t-auth profile list'", args[1])
		}
		if err := SetCurrentProfile(args[1]); err != nil {
			return err
		}
		return e.out.emit(map[string]any{"current": sanitizeProfile(args[1])},
			func() { e.out.ok("now using profile " + sanitizeProfile(args[1])) })

	case "remove":
		if len(args) < 2 {
			return errors.New("usage: ab0t-auth profile remove <name>")
		}
		removed, err := DeleteProfile(args[1])
		if err != nil {
			return err
		}
		return e.out.emit(map[string]any{"removed": removed, "profile": sanitizeProfile(args[1])}, func() {
			if removed {
				e.out.ok("removed profile " + sanitizeProfile(args[1]))
				return
			}
			e.out.printf("no profile named %s\n", sanitizeProfile(args[1]))
		})
	}
	return fmt.Errorf("unknown subcommand %q: use list, use, or remove", sub)
}

func cmdOrgs(ctx context.Context, e *env, _ any, _ []string) error {
	if !e.cred.Present() {
		return errNoCredential
	}
	res, err := e.client().GetMyOrganizations(ctx, e.cred.Value)
	if err != nil {
		return err
	}
	return e.out.emit(map[string]any{"organizations": res, "count": len(res)}, func() {
		if len(res) == 0 {
			e.out.printf("this credential belongs to no organizations\n")
			return
		}
		// Show the tenancy facts, not just names: the ROLE is what the caller
		// can do here, PARENT is whether this org sits under another, and
		// personal/default are why a user has several in the first place.
		for _, o := range res {
			marks := ""
			if o.IsDefault {
				marks += " [default]"
			}
			if o.IsPersonal {
				marks += " [personal]"
			}
			if o.ParentID != "" {
				marks += " [sub-org of " + o.ParentID + "]"
			}
			if o.WorkspaceType != "" {
				marks += " [" + o.WorkspaceType + "]"
			}
			e.out.printf("%-28s %-14s %s%s\n", o.ID, o.Role, o.Name, marks)
		}
	})
}

func cmdOrgTree(ctx context.Context, e *env, _ any, args []string) error {
	if err := needArgs(args, 1, "org-tree <org-id>"); err != nil {
		return err
	}
	if !e.cred.Present() {
		return errNoCredential
	}
	res, err := e.client().GetOrgHierarchy(ctx, args[0], e.cred.Value)
	if err != nil {
		return err
	}
	return e.out.emit(res, func() {
		// Render the TREE, indented. Companies of companies are the point of this
		// verb; a flat summary would hide the thing it exists to show.
		res.WalkOrgTree(func(n *auth.OrgHierarchyResponse, depth int) {
			if n.Organization == nil {
				return
			}
			e.out.printf("%s%s  %s  (teams %d, users %d)\n",
				strings.Repeat("  ", depth), n.Organization.Slug, n.Organization.ID,
				n.TeamCount, n.UserCount)
		})
	})
}
