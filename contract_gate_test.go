package authclient

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// contract_gate_test.go — the CLASS-34 bidirectional contract gate.
//
// It pins the auth-service wire contract in scripts/api_contract.json (top-level
// request/response field names per endpoint, derived from the goauth handler
// structs) and REFLECTS the paired SDK request/response Go structs, failing the
// build (this runs under `go test`, which CI gates on) on any of the four drift
// categories:
//
//	1 MISSING-ON-REQUEST  — API accepts a field the SDK request struct omits.
//	2 MISSING-ON-RESPONSE — API returns a field the SDK response struct omits.
//	3 OVER-EXPOSURE       — SDK sends/reads a field the API set lacks (footgun), unless allow-listed.
//	4 ENVELOPE-MISMATCH   — the SDK binding's array/object kind must equal the API envelope.
//
// It is deterministic (no network) and reproducible. Every one of the CLASS-34
// findings this ticket fixed is a fixture here (or, for the two custom-MarshalJSON
// request bodies, is delegated to its named wire-shape test — see the snapshot
// notes). HOUSE STANDARD: adopt this harness in the other Go SDKs.

// contractEntry is one endpoint's pinned API truth (see scripts/api_contract.json).
type contractEntry struct {
	Note                 string            `json:"note"`
	RequestAccepts       []string          `json:"request_accepts"`
	RequestCustomMarshal bool              `json:"request_custom_marshal"`
	ResponseReturns      []string          `json:"response_returns"`
	ResponseEnvelope     string            `json:"response_envelope"`
	AllowRequestExtra    map[string]string `json:"allow_request_extra"`
	AllowResponseExtra   map[string]string `json:"allow_response_extra"`
}

// binding ties an endpoint to the SDK request/response Go types. For an array
// response, resp is the ELEMENT type and respArray is true.
type binding struct {
	req       any
	resp      any
	respArray bool
}

// contractBindings pairs each pinned endpoint with its SDK structs. Keep in sync
// with scripts/api_contract.json — the gate fails if either side has an orphan.
var contractBindings = map[string]binding{
	"GET /organizations/{org_id}/users":                          {resp: OrgMember{}, respArray: true},
	"GET /organizations/{org_id}/login-config":                   {resp: LoginConfig{}},
	"PUT /organizations/{org_id}/login-config":                   {req: LoginConfig{}, resp: LoginConfig{}},
	"POST /zanzibar/stores/{store_id}/authorization-models":      {resp: WriteAuthorizationModelResponse{}},
	"GET /zanzibar/stores/{store_id}/authorization-models":       {resp: ListAuthorizationModelsResponse{}},
	"GET /organizations/{org_id}/hierarchy":                      {resp: OrgHierarchyResponse{}},
	"GET /organizations/{org_id}/sessions":                       {resp: OrgSessionsResponse{}},
	"DELETE /organizations/{org_id}/users/{user_id}/sessions":    {resp: SessionRevokeResponse{}},
	"POST /auth/register":                                        {req: RegisterRequest{}},
	"POST /organizations/{slug}/auth/register":                   {req: OrgRegisterRequest{}},
	"POST /api-keys/":                                            {req: APIKeyCreate{}},
	"PUT /api-keys/{key_id}":                                     {req: APIKeyUpdate{}},
	"POST /providers/":                                           {req: ProviderConfigCreate{}},
	"PUT /providers/{provider_id}":                               {req: ProviderConfigUpdate{}},
	"POST /organizations/{org_id}/invite":                        {req: OrganizationInvite{}, resp: InviteResult{}},
	"POST /auth/oauth/register":                                  {req: ClientRegistration{}},
	"GET /teams/{team_id}/members":                               {resp: TeamMember{}, respArray: true},
	"GET /teams/{team_id}/permissions":                           {resp: TeamPermissionsResponse{}},
	"POST /organizations/":                                       {req: OrganizationCreate{}},
	"PUT /organizations/{org_id}":                                {req: OrganizationUpdate{}},
	"GET /organizations/{org_id}":                                {resp: Organization{}},
	"POST /auth/validate-token":                                  {req: TokenValidationRequest{}},
	"PUT /organizations/{org_id}/users/{user_id}":                {req: OrgRoleUpdate{}},
	"GET /organizations/{org_id}/clients":                        {resp: OrgClientSafe{}, respArray: true},
	"POST /zanzibar/stores/{store_id}/write":                     {resp: TransactResponse{}},
	"GET /zanzibar/stores/{store_id}/assertions/{model_id}":      {resp: AssertionsResponse{}},
	"POST /zanzibar/stores/{store_id}/assertions/{model_id}/run": {resp: AssertionsRunResponse{}},
	"PUT /zanzibar/stores/{store_id}/assertions/{model_id}":      {req: PutAssertionsRequest{}, resp: MessageResponse{}},
}

// jsonFieldSet returns the set of TOP-LEVEL json field names a struct marshals,
// recursing anonymous embedded structs (which promote their fields) and skipping
// json:"-". It reflects the declared tags, so it sees every field regardless of
// omitempty — the completeness a value-marshal (which drops zero fields) cannot give.
func jsonFieldSet(v any) map[string]bool {
	out := map[string]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			name := strings.Split(tag, ",")[0]
			if name == "-" {
				continue
			}
			if f.Anonymous && name == "" {
				walk(f.Type) // embedded struct promotes its fields
				continue
			}
			if name == "" {
				name = f.Name
			}
			out[name] = true
		}
	}
	walk(reflect.TypeOf(v))
	return out
}

func loadContract(t *testing.T) map[string]contractEntry {
	t.Helper()
	raw, err := os.ReadFile("scripts/api_contract.json")
	if err != nil {
		t.Fatalf("read api_contract.json: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse api_contract.json: %v", err)
	}
	out := map[string]contractEntry{}
	for k, v := range doc {
		if strings.HasPrefix(k, "_") {
			continue
		}
		var e contractEntry
		if err := json.Unmarshal(v, &e); err != nil {
			t.Fatalf("parse entry %q: %v", k, err)
		}
		out[k] = e
	}
	return out
}

func sortedMissing(want []string, have map[string]bool) []string {
	var m []string
	for _, w := range want {
		if !have[w] {
			m = append(m, w)
		}
	}
	sort.Strings(m)
	return m
}

func sortedExtra(have map[string]bool, want []string, allow map[string]string) []string {
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	var x []string
	for h := range have {
		if !wantSet[h] && allow[h] == "" {
			x = append(x, h)
		}
	}
	sort.Strings(x)
	return x
}

// TestContractGate is the CLASS-34 gate. It fails on any non-allow-listed drift.
func TestContractGate(t *testing.T) {
	contract := loadContract(t)

	// Sync: every pinned endpoint must have a binding and vice versa.
	for id := range contract {
		if _, ok := contractBindings[id]; !ok {
			t.Errorf("contract endpoint %q has no SDK binding (add it to contractBindings)", id)
		}
	}
	for id := range contractBindings {
		if _, ok := contract[id]; !ok {
			t.Errorf("SDK binding %q has no contract entry (add it to scripts/api_contract.json)", id)
		}
	}

	for id, e := range contract {
		b, ok := contractBindings[id]
		if !ok {
			continue
		}

		// --- Request side ---
		if e.RequestAccepts != nil && !e.RequestCustomMarshal {
			if b.req == nil {
				t.Errorf("[%s] contract has request_accepts but binding has no req struct", id)
			} else {
				have := jsonFieldSet(b.req)
				if miss := sortedMissing(e.RequestAccepts, have); len(miss) > 0 {
					t.Errorf("[%s] MISSING-ON-REQUEST: API accepts %v but the SDK request struct omits them", id, miss)
				}
				if extra := sortedExtra(have, e.RequestAccepts, e.AllowRequestExtra); len(extra) > 0 {
					t.Errorf("[%s] OVER-EXPOSURE (request): SDK sends %v which the API does not accept (footgun); remove them or allow-list with a reason", id, extra)
				}
			}
		}

		// --- Response side ---
		if e.ResponseReturns != nil {
			if b.resp == nil {
				t.Errorf("[%s] contract has response_returns but binding has no resp struct", id)
			} else {
				have := jsonFieldSet(b.resp)
				if miss := sortedMissing(e.ResponseReturns, have); len(miss) > 0 {
					t.Errorf("[%s] MISSING-ON-RESPONSE: API returns %v but the SDK response struct omits them", id, miss)
				}
				if extra := sortedExtra(have, e.ResponseReturns, e.AllowResponseExtra); len(extra) > 0 {
					t.Errorf("[%s] OVER-EXPOSURE (response): SDK reads %v the API never sends; remove or allow-list with a reason", id, extra)
				}
			}
			// --- Envelope (category 4) ---
			wantArray := e.ResponseEnvelope == "array"
			if wantArray != b.respArray {
				t.Errorf("[%s] ENVELOPE-MISMATCH: contract says response_envelope=%q but the SDK binding respArray=%v", id, e.ResponseEnvelope, b.respArray)
			}
		}
	}
}

// TestContractGate_MechanismDetectsDrift proves the gate's primitives actually
// flag each drift category (so a green TestContractGate means "no drift", not
// "the check is inert").
func TestContractGate_MechanismDetectsDrift(t *testing.T) {
	type sdkReq struct {
		A string `json:"a"`
		B string `json:"b"`
		// resource_type-style footgun: present on SDK, not accepted by API.
		Extra string `json:"extra"`
	}
	have := jsonFieldSet(sdkReq{})
	api := []string{"a", "b", "c"} // API also accepts "c" (SDK omits it)

	if miss := sortedMissing(api, have); len(miss) != 1 || miss[0] != "c" {
		t.Fatalf("MISSING detection broken: %v", miss)
	}
	if extra := sortedExtra(have, api, nil); len(extra) != 1 || extra[0] != "extra" {
		t.Fatalf("OVER-EXPOSURE detection broken: %v", extra)
	}
	// Allow-listing suppresses the over-exposure.
	if extra := sortedExtra(have, api, map[string]string{"extra": "reason"}); len(extra) != 0 {
		t.Fatalf("allow-list not honored: %v", extra)
	}
	// Embedded structs promote their fields (AdminUserUpdate embeds UserUpdate).
	adm := jsonFieldSet(AdminUserUpdate{})
	if !adm["status"] || !adm["name"] {
		t.Fatalf("embedded promotion broken: %v", adm)
	}
	// json:"-" is excluded (WriteAuthorizationModelRequest.Model).
	if jsonFieldSet(WriteAuthorizationModelRequest{})["Model"] {
		t.Fatalf("json:\"-\" field leaked into the set")
	}
}
