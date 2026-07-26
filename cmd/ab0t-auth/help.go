package main

// help.go — the tool as an interactive support page.
//
// WHY THIS FILE EXISTS
//
// A user-journey review of this CLI (pmm/02) found that 20 of 28 customer
// journeys stalled on the same class of defect: the tool KNEW what the customer
// would want next and did not say it. `can` returned DENIED and never mentioned
// `why`. `login` succeeded and never mentioned `whoami`. `doctor` — the single
// most useful verb when something is wrong — was reachable only by reading the
// full command list, which is what a stuck person is least likely to do.
//
// None of that is a missing feature. It is information already in the binary,
// withheld. That class of defect is paid for by every customer, individually,
// forever; fixing it is paid for once, here.
//
// The cold walk also found that `help can` printed the GENERIC top-level page and
// exited 0 — the customer asked a specific question, got a different answer, and
// was told it succeeded. Both `help <verb>` and `<verb> --help` now resolve to the
// same deep document, because customers reach for both and neither is wrong.
//
// WHAT "DEEP" MEANS HERE
//
// A synopsis and a flag list is a reference card. It is useful only to someone who
// already knows what the verb is for. Deep help answers the four things a person
// actually needs, in the order they need them:
//
//	Purpose   — what this is FOR, in their words, not the endpoint it calls
//	Example   — a worked example WITH ITS REAL OUTPUT, so the shape is unambiguous
//	Failures  — the errors they will hit and what each one MEANS
//	Next      — what people typically run after this
//
// If help does not reduce the chance of the next support question, it is not help.

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// helpDoc is the deep help for one verb.
type helpDoc struct {
	// Purpose says what the verb is for, in customer vocabulary.
	Purpose string
	// Example is a worked example including its real output. The output matters
	// more than the command: it is how a reader (or an agent) learns the shape of
	// the answer without running it.
	Example string
	// Failures maps a failure the customer will actually hit to what it means and
	// what to do. Not an error-code table — the two or three that really happen.
	Failures [][2]string
	// Next lists what people typically run after this verb. This is the
	// progressive-disclosure payload; it comes straight from the `Next journey:`
	// field of the journeys in pmm/02.
	Next []string
	// SeeAlso points at verbs that answer an adjacent question.
	SeeAlso []string
}

// commonCommands is the ~10 things people actually do, in the order a newcomer
// meets them rather than alphabetically. Ordering IS the teaching: a list sorted
// by name tells a first-time reader nothing about where to start.
var commonCommands = []struct{ cmd, why string }{
	{"ab0t-auth doctor", "Start here when something is wrong — checks config, connectivity and credential"},
	{"ab0t-auth health", "Is the auth service up? Needs no credential"},
	{"ab0t-auth login --key ab0t_sk_…", "Store a service key (or --email for a person)"},
	{"ab0t-auth whoami", "Who am I currently authenticated as?"},
	{"ab0t-auth can user:alice view doc:123 --store S", "May this subject do this to this object?"},
	{"ab0t-auth why user:alice view doc:123 --store S", "Why was that allowed or denied?"},
	{"ab0t-auth grant user:alice owner doc:123 --store S", "Give someone access"},
	{"ab0t-auth who-can doc:123 view --store S", "Who can see this? — access review"},
	{"ab0t-auth what-can user:alice view doc --store S", "What can this subject reach? — least privilege"},
	{"ab0t-auth help <verb>", "Deep help for any verb: purpose, example, failures, what's next"},
}

// helpDocs is the per-verb deep help. Every verb in `commands` must have an entry;
// TestEveryVerbHasDeepHelp fails the build if one is missing, so a new verb cannot
// ship undocumented.
var helpDocs = map[string]helpDoc{
	"login": {
		Purpose: `Authenticate once and store the credential, so later commands do not need --token.

Two kinds of credential: a SERVICE KEY (ab0t_sk_…, for a machine or a service) via
--key, or a PERSON via --email/--password. Both end up in the same place.`,
		Example: `  $ ab0t-auth login --key ab0t_sk_live_abc123
  OK stored API key ab0t_sk_******** in /home/you/.config/ab0t/auth.json

The key is validated with the service before it is stored, so a bad key fails here
rather than on your next command.`,
		Failures: [][2]string{
			{"the auth service rejected that key", "The key is wrong, revoked, or for a different environment. Check --server."},
			{"--password is required when stdin is not a terminal", "You are in CI or a container. Pass --password, or better, use --key with a service account."},
			{"connection refused / no such host", "Wrong --server, or no network. Try 'ab0t-auth health'."},
		},
		Next:    []string{"whoami — confirm who you now are", "doctor — confirm everything is wired correctly"},
		SeeAlso: []string{"logout", "whoami", "doctor"},
	},
	"logout": {
		Purpose: `Remove the stored credential from this machine.

Only affects local storage. It does NOT revoke the credential — anyone else holding
it can still use it. To kill a leaked key you need the auth service, not this.`,
		Example: `  $ ab0t-auth logout
  Remove the stored credential at /home/you/.config/ab0t/auth.json? Type 'yes' to confirm: yes
  OK removed /home/you/.config/ab0t/auth.json

  $ ab0t-auth logout --yes     # no prompt, for scripts`,
		Failures: [][2]string{
			{"no stored credential at …", "Nothing to remove. Not an error."},
			{"cancelled", "You did not type 'yes'. Nothing changed."},
		},
		Next:    []string{"login — authenticate again", "whoami — confirm you are now anonymous"},
		SeeAlso: []string{"login", "whoami"},
	},
	"whoami": {
		Purpose: `Show the identity behind the credential currently in effect, and WHERE that
credential came from.

The source line is the point. "Why is it using the wrong account?" is almost always
an environment variable shadowing the stored credential, and this is how you see it.`,
		Example: `  $ ab0t-auth whoami
  user:        u_01H8XK
  org:         acme
  email:       you@example.com
  credential:  ab0t_sk_******** (api-key)
  source:      /home/you/.config/ab0t/auth.json

Precedence: --token  >  $AB0T_AUTH_TOKEN  >  $AUTH_SERVICE_KEY  >  stored file.`,
		Failures: [][2]string{
			{"no credential", "Nothing is set anywhere. Run 'ab0t-auth login'."},
			{"credential is not valid", "It expired or was revoked. Run 'ab0t-auth login' again."},
		},
		Next:    []string{"doctor — full check of config and connectivity", "can — ask an authorization question"},
		SeeAlso: []string{"login", "doctor"},
	},
	"can": {
		Purpose: `Ask whether a subject may perform a permission on an object. This is the
question the whole service exists to answer.

Ids are TYPED: "user:alice", not "alice". The type prefix is what tells the service
whether you mean a user, a team or a service account — "alice" alone is ambiguous
and is rejected rather than guessed at.

A DENIED is a real answer, not an error. It usually means no relationship exists
yet — run 'why' to see the reasoning.`,
		Example: `  $ ab0t-auth can user:alice view doc:123 --store my-store
  DENIED  user:alice view doc:123
    reason: no relation

  $ echo $?
  2

Exit code carries the answer, so this works in a script:
  if ab0t-auth can user:alice view doc:123 --store my-store; then deploy; fi

  0 = ALLOWED    2 = DENIED    1 = error    3 = no credential`,
		Failures: [][2]string{
			{"is not a typed Zanzibar id", `Add the type prefix: "user:alice" rather than "alice".`},
			{"a store is required", "Pass --store, or set $AB0T_ZANZIBAR_STORE. A store is the permissions database for your app."},
			{"DENIED when you expected ALLOWED", "Not a failure. Run 'why' for the reasoning, then 'grant' if the relationship is genuinely missing."},
		},
		Next:    []string{"why — see the reasoning behind that answer", "grant — create the relationship if it is missing", "who-can — see everyone who can do this"},
		SeeAlso: []string{"why", "grant", "who-can"},
	},
	"why": {
		Purpose: `Explain an authorization decision: the verdict, the reason, and the chain of
relationships the service followed to get there.

Use this the moment a 'can' result surprises you. It is the difference between
"the system says no" and "the system says no BECAUSE alice is not on the team that
owns this document".`,
		Example: `  $ ab0t-auth why user:alice view doc:123 --store my-store
  ALLOWED  user:alice view doc:123
    reason: via group membership
    path:   user:alice -> group:eng#member -> doc:123#viewer

The path is read left to right: alice is a member of group:eng, and group:eng is a
viewer of doc:123.`,
		Failures: [][2]string{
			{"empty path on an ALLOWED", "The permission was direct — there was no chain to follow."},
			{"a store is required", "Pass --store or set $AB0T_ZANZIBAR_STORE."},
		},
		Next:    []string{"grant / revoke — change the relationship you just saw", "who-can — everyone with this permission on the object"},
		SeeAlso: []string{"can", "grant", "who-can"},
	},
	"who-can": {
		Purpose: `List every subject that may perform a permission on one object.

This is the ACCESS REVIEW verb: "who can see this document?" Group memberships are
expanded, so you get the people, not the groups — which is what an auditor is
actually asking for.`,
		Example: `  $ ab0t-auth who-can doc:123 view --store my-store
  user:alice
  user:bob

  $ ab0t-auth who-can doc:123 view --store my-store --json | jq -r '.subjects[]'

Use --json to feed an access-review spreadsheet or an audit artefact.`,
		Failures: [][2]string{
			{"empty list", "Nobody has that permission. A real answer, not an error."},
			{"a store is required", "Pass --store or set $AB0T_ZANZIBAR_STORE."},
		},
		Next:    []string{"why — how a particular subject got access", "revoke — remove access you did not expect", "what-can — the same question from the subject's side"},
		SeeAlso: []string{"what-can", "why", "revoke"},
	},
	"what-can": {
		Purpose: `List every object OF ONE TYPE that a subject may act on.

This is the LEAST-PRIVILEGE verb: "what can this service account actually reach?"
Note it needs the object TYPE — it answers per type, not across everything, so run
it once per type you care about.`,
		Example: `  $ ab0t-auth what-can user:alice view doc --store my-store
  doc:123
  doc:456

Read as: of the objects of type "doc", alice can view these two.`,
		Failures: [][2]string{
			{"empty list", "The subject can reach nothing of that type. A real answer."},
			{"you do not know which types exist", "This verb cannot enumerate types for you. Take the list from your own schema."},
		},
		Next:    []string{"who-can — the same question from the object's side", "revoke — shrink an over-broad grant"},
		SeeAlso: []string{"who-can", "why", "revoke"},
	},
	"grant": {
		Purpose: `Write a relationship: subject —relation→ object. This is how access is created.

Note that RELATION is not the same as the PERMISSION you check with 'can'. You
usually grant a role-like relation ("owner", "editor", "member") and check a
permission ("view", "edit") that the service derives from it.

Idempotent: granting something that already exists is not an error.`,
		Example: `  $ ab0t-auth grant user:alice owner doc:123 --store my-store
  OK granted user:alice owner doc:123

  $ ab0t-auth can user:alice view doc:123 --store my-store
  ALLOWED  user:alice view doc:123

Always verify with 'can' afterwards — that is your evidence the change did what you
intended, and it is what belongs in the ticket.`,
		Failures: [][2]string{
			{"relationship write refused", "The service rejected it — usually an unknown relation name for that object type."},
			{"is not a typed Zanzibar id", `Both subject and object need a type prefix: "user:alice", "doc:123".`},
			{"granted but 'can' still says DENIED", "You granted a relation that does not confer that permission. Run 'why'."},
		},
		Next:    []string{"can — verify the grant did what you intended", "who-can — confirm the full access list is still correct"},
		SeeAlso: []string{"revoke", "can", "why"},
	},
	"revoke": {
		Purpose: `Remove a relationship: subject —relation→ object.

IMPORTANT: this revokes a RELATIONSHIP, not a credential. If you are here because a
key or token leaked, this is the wrong verb — a leaked credential must be revoked at
the auth service itself; removing relationships does not disable it.

Idempotent: removing a relationship that is not there is not an error.`,
		Example: `  $ ab0t-auth revoke user:alice owner doc:123 --store my-store
  OK revoked user:alice owner doc:123

  $ ab0t-auth can user:alice view doc:123 --store my-store
  DENIED  user:alice view doc:123`,
		Failures: [][2]string{
			{"you meant to revoke a KEY", "This verb cannot do that. Revoke the credential in the auth service; 'logout' only clears local storage."},
			{"revoked but access remains", "Access came from another path — a group or a second relation. Run 'why' to find it."},
		},
		Next:    []string{"can — verify the access is actually gone", "why — if access remains, find the other path"},
		SeeAlso: []string{"grant", "why", "who-can"},
	},
	"health": {
		Purpose: `Check that the auth service is reachable and healthy.

Needs NO credential, which makes it the right first command when you are not sure
whether the problem is you or the service.`,
		Example: `  $ ab0t-auth health
  status:  healthy`,
		Failures: [][2]string{
			{"connection refused / no such host", "Wrong --server or no network. The service may be fine."},
			{"a 5xx", "The service itself is unhealthy — this is not your configuration."},
		},
		Next:    []string{"doctor — if health is fine but your commands still fail, the problem is local"},
		SeeAlso: []string{"doctor"},
	},
	"doctor": {
		Purpose: `Diagnose your configuration and connectivity end to end. START HERE when
something is wrong.

Checks the server URL, whether a credential is present and where it came from, the
permissions on the credential file, whether the service is reachable, and whether
your credential is actually valid.

Reports EVERY check rather than stopping at the first failure — the second failure
is often what explains the first.`,
		Example: `  $ ab0t-auth doctor
  PASS  auth service URL             https://auth.service.ab0t.com
  PASS  credential found             ab0t_sk_******** (api-key) from /home/you/.config/ab0t/auth.json
  PASS  credential file permissions  0600
  PASS  service reachable            healthy
  PASS  credential valid             user=u_01H8XK org=acme

Exits non-zero if any check fails, so it works as a CI preflight step.`,
		Failures: [][2]string{
			{"credential found: FAIL", "Nothing is set. Run 'ab0t-auth login'."},
			{"credential file permissions: FAIL", "The file is readable by other users. Fix with: chmod 600 on the path shown."},
			{"service reachable: FAIL", "Network or wrong --server. The service may be fine — check 'health'."},
			{"credential valid: FAIL", "It expired or was revoked. Run 'ab0t-auth login' again."},
		},
		Next:    []string{"login — if the credential check failed", "health — if you suspect the service rather than your setup"},
		SeeAlso: []string{"health", "whoami", "login"},
	},
}

// renderVerbHelp writes the deep help for one verb.
func renderVerbHelp(w io.Writer, name string, o *output) {
	cmd := lookup(name)
	doc, ok := helpDocs[name]
	if cmd == nil || !ok {
		fmt.Fprintf(w, "no help for %q\n", name)
		return
	}

	fmt.Fprintf(w, "%s — %s\n\n", o.paint(ansiBold, "ab0t-auth "+name), cmd.summary)
	fmt.Fprintf(w, "%s\n  ab0t-auth %s\n\n", o.paint(ansiBold, "USAGE"), cmd.usage)

	fmt.Fprintf(w, "%s\n", o.paint(ansiBold, "WHAT IT'S FOR"))
	fmt.Fprintf(w, "%s\n\n", indent(doc.Purpose, "  "))

	fmt.Fprintf(w, "%s\n%s\n\n", o.paint(ansiBold, "EXAMPLE"), doc.Example)

	if len(doc.Failures) > 0 {
		fmt.Fprintf(w, "%s\n", o.paint(ansiBold, "WHEN IT GOES WRONG"))
		for _, f := range doc.Failures {
			fmt.Fprintf(w, "  %s\n%s\n", f[0], indent(f[1], "      "))
		}
		fmt.Fprintln(w)
	}
	if len(doc.Next) > 0 {
		fmt.Fprintf(w, "%s\n", o.paint(ansiBold, "WHAT PEOPLE USUALLY DO NEXT"))
		for _, n := range doc.Next {
			fmt.Fprintf(w, "  ab0t-auth %s\n", n)
		}
		fmt.Fprintln(w)
	}
	if len(doc.SeeAlso) > 0 {
		fmt.Fprintf(w, "%s  %s\n\n", o.paint(ansiBold, "SEE ALSO"), strings.Join(doc.SeeAlso, ", "))
	}
	fmt.Fprintf(w, "Run 'ab0t-auth %s --help' for the full flag list.\n", name)
}

func indent(s, pad string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l == "" {
			continue
		}
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

// verbNames returns every registered verb, sorted — used by tests and by the
// help index.
func verbNames() []string {
	out := make([]string, 0, len(commands))
	for _, c := range commands {
		out = append(out, c.name)
	}
	sort.Strings(out)
	return out
}

// nextSteps prints what people usually do after this verb.
//
// This is the progressive-disclosure surface, and the reason it is worth having is
// arithmetic: the tool already knows the customer just ran `can` and got DENIED.
// Withholding "run 'why' to see the reasoning" means every customer pays for that
// knowledge separately — in docs, in search, or in a support ticket. Printing it
// costs one line, once.
//
// Rules it must obey, or it becomes noise people learn to ignore:
//   - stderr, never stdout, so it cannot contaminate --json or a piped result;
//   - silent under --quiet and --json, because a script did not ask for advice;
//   - at most two suggestions — a list of ten is a menu, not a hint.
func nextSteps(o *output, verb string, ok bool) {
	if o.quiet || o.jsonM {
		return
	}
	var hints []string
	switch {
	case verb == "can" && !ok:
		// The single highest-value hint in the tool: six journeys stalled here.
		hints = []string{
			"why " + "<same arguments>  — see the reasoning behind this answer",
			"grant <subject> <relation> <object>  — if the relationship is genuinely missing",
		}
	case verb == "can" && ok:
		hints = []string{"who-can <object> <permission>  — everyone else who can do this"}
	case verb == "login":
		hints = []string{"whoami  — confirm who you now are", "doctor  — confirm everything is wired correctly"}
	case verb == "logout":
		hints = []string{"login  — authenticate again"}
	case verb == "whoami":
		hints = []string{"doctor  — full check of config and connectivity"}
	case verb == "grant", verb == "revoke":
		hints = []string{"can <subject> <permission> <object>  — verify the change did what you intended"}
	case verb == "health":
		hints = []string{"doctor  — if the service is healthy but your commands still fail, the problem is local"}
	case verb == "who-can", verb == "what-can":
		hints = []string{"why <subject> <permission> <object>  — how a particular subject got access"}
	case verb == "doctor" && ok:
		hints = []string{"can <subject> <permission> <object> --store S  — ask an authorization question"}
	}
	if len(hints) == 0 {
		return
	}
	fmt.Fprintf(o.errw, "\n%s\n", o.paint(ansiDim, "next:"))
	for _, h := range hints {
		fmt.Fprintf(o.errw, "%s\n", o.paint(ansiDim, "  ab0t-auth "+h))
	}
}
