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
type storeOpts struct{ store string }

func storeFlags(fs *flag.FlagSet) any {
	o := &storeOpts{}
	fs.StringVar(&o.store, "store", os.Getenv("AB0T_ZANZIBAR_STORE"), "Zanzibar store id (or $AB0T_ZANZIBAR_STORE)")
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
		if err := saveCredential(&storedFile{Token: key, AuthService: e.g.server, OrgID: res.OrgID}); err != nil {
			return err
		}
		return e.out.emit(map[string]any{"saved": true, "kind": "api-key", "path": credPath(), "org_id": res.OrgID},
			func() { e.out.ok("stored API key " + mask(key) + " in " + credPath()) })
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
	if err := saveCredential(&storedFile{Token: ts.AccessToken, AuthService: e.g.server, OrgID: org, Email: email}); err != nil {
		return err
	}
	return e.out.emit(map[string]any{"saved": true, "kind": "token", "path": credPath(), "email": email},
		func() { e.out.ok("logged in as " + email + "; credential stored in " + credPath()) })
}

func cmdLogout(_ context.Context, e *env, opts any, _ []string) error {
	// Destructive actions confirm — but only when a human is there to answer.
	// A prompt that blocks in CI is a hang, not a safeguard, so a non-TTY stdin
	// proceeds and --yes/-y is always available.
	if !opts.(*yesOpts).yes && isTerminal(os.Stdin) && !e.g.quiet {
		fmt.Fprintf(os.Stderr, "Remove the stored credential at %s? Type 'yes' to confirm: ", credPath())
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			return errors.New("cancelled")
		}
	}
	removed, err := deleteCredential()
	if err != nil {
		return err
	}
	return e.out.emit(map[string]any{"removed": removed, "path": credPath()}, func() {
		if removed {
			e.out.ok("removed " + credPath())
			return
		}
		e.out.printf("no stored credential at %s\n", credPath())
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
	st := e.client().Store(store, e.cred.Value)
	var err error
	if grant {
		err = st.RelateID(ctx, rest[0], rest[1], rest[2])
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
	} else if e.cred.Source == credPath() {
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
