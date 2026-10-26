// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package teams_test

// Teams tests driven through the REAL registered router (routes.Route installs
// the Guard and the typed CRUD). The teams surface had no tests; these pin the
// tenancy contract of the (owner, name) key: an unauthenticated caller is
// refused, a caller lists and reaches only its own organization's teams, no
// request names another tenant's team (get, update and delete all miss with
// 404 and leave the row untouched), a re-used name conflicts, a team may not
// name another organization's people as members, and an update changes
// content only - never the name, the created stamp, or the owning org.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"

	"github.com/hanzoai/iam/internal/testhttp"
)

const signingKid = "cert-hanzo"

type harness struct {
	app *zip.App
	key *rsa.PrivateKey
	db  orm.DB
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	_ = schema.Kinds()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "teams.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, "admin", signingKid, pemOf(t, key))
	seedUser(t, db, "admin", "root", true)    // SuperAdmin
	seedUser(t, db, "acme", "boss", true)     // org-admin of acme
	seedUser(t, db, "acme", "alice", false)   // regular user in acme
	seedUser(t, db, "other", "mallory", true) // org-admin of another tenant

	// Authority rides on membership rows, not the user row's flags alone.
	for _, m := range [][3]string{
		{"acme/boss", "acme", store.RoleAdmin},
		{"acme/alice", "acme", store.RoleMember},
		{"other/mallory", "other", store.RoleAdmin},
	} {
		if _, err := store.EnsureMembership(context.Background(), db, m[0], m[1], m[2]); err != nil {
			t.Fatalf("seed membership %s@%s: %v", m[0], m[1], err)
		}
	}

	app := zip.New(zip.Config{AppName: "teams-test", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &harness{app: app, key: key, db: db}
}

func (h *harness) token(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"tokenType": "access-token", "iss": "https://hanzo.id", "aud": "hanzo-test",
		"sub": sub,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = signingKid
	s, err := tok.SignedString(h.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func (h *harness) do(t *testing.T, method, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

func rows(m map[string]any) []map[string]any {
	var raw []any
	for _, v := range m {
		if a, ok := v.([]any); ok {
			raw = append(raw, a...)
		}
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if o, ok := r.(map[string]any); ok {
			out = append(out, o)
		}
	}
	return out
}

func find(m map[string]any, name string) map[string]any {
	for _, o := range rows(m) {
		if n, _ := o["name"].(string); n == name {
			return o
		}
	}
	return nil
}

func seedCert(t *testing.T, db orm.DB, owner, name, privPEM string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	keyring.Set(name, privPEM)
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
}

func seedUser(t *testing.T, db orm.DB, owner, name string, admin bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.IsAdmin = admin
	u.PasswordHash = "$argon2id$SENTINEL"
	u.PasswordType = "argon2id"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}

// An unauthenticated caller is refused at the Guard.
func TestTeams_UnauthenticatedIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, p := range []struct{ method, path string }{
		{"GET", "/v1/iam/teams"},
		{"POST", "/v1/iam/teams"},
		{"GET", "/v1/iam/teams/eng"},
		{"PUT", "/v1/iam/teams/eng"},
		{"DELETE", "/v1/iam/teams/eng"},
	} {
		code, _ := h.do(t, p.method, p.path, "", "")
		if code != 401 {
			t.Errorf("%s %s unauthenticated = %d, want 401", p.method, p.path, code)
		}
	}
}

// Lifecycle: an org-admin creates a team, lists it, updates its content, and
// deletes it.
func TestTeams_Lifecycle(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "acme/boss")

	code, _ := h.do(t, "POST", "/v1/iam/teams", boss,
		`{"name":"eng","displayName":"Engineering","users":["alice"]}`)
	if code != 200 {
		t.Fatalf("create = %d, want 200", code)
	}

	code, list := h.do(t, "GET", "/v1/iam/teams", boss, "")
	if code != 200 {
		t.Fatalf("list = %d, want 200", code)
	}
	if find(list, "eng") == nil {
		t.Fatalf("list does not contain eng: %v", list)
	}

	code, _ = h.do(t, "PUT", "/v1/iam/teams/eng", boss,
		`{"name":"eng","displayName":"Platform","users":["alice","boss"]}`)
	if code != 200 {
		t.Fatalf("update = %d, want 200", code)
	}
	code, got := h.do(t, "GET", "/v1/iam/teams/eng", boss, "")
	if code != 200 {
		t.Fatalf("get = %d, want 200", code)
	}
	team := find(got, "eng")
	if team == nil {
		team = got
	}
	if d, _ := team["displayName"].(string); d != "Platform" {
		t.Errorf("displayName = %v, want Platform", team["displayName"])
	}

	code, _ = h.do(t, "DELETE", "/v1/iam/teams/eng", boss, "")
	if code != 200 {
		t.Fatalf("delete = %d, want 200", code)
	}
	code, _ = h.do(t, "GET", "/v1/iam/teams/eng", boss, "")
	if code != 404 {
		t.Fatalf("get after delete = %d, want 404", code)
	}
}

// A name already used in the organization is refused.
func TestTeams_CreateRefusesADuplicateName(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "acme/boss")
	body := `{"name":"eng","users":["alice"]}`
	if code, _ := h.do(t, "POST", "/v1/iam/teams", boss, body); code != 200 {
		t.Fatalf("first create = %d, want 200", code)
	}
	if code, _ := h.do(t, "POST", "/v1/iam/teams", boss, body); code != 409 {
		t.Fatalf("duplicate create = %d, want 409", code)
	}
}

// A team may only name people of its own organization: naming another
// tenant's member (or the platform's super-admin) is refused.
func TestTeams_CannotNameAnotherOrgsPeople(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "acme/boss")
	for _, users := range []string{`["root"]`, `["mallory"]`, `["alice","root"]`} {
		code, _ := h.do(t, "POST", "/v1/iam/teams", boss,
			`{"name":"x","users":`+users+`}`)
		if code == 200 {
			t.Errorf("create with users=%s = 200, want refusal", users)
		}
	}
	// The refused writes left nothing behind.
	_, list := h.do(t, "GET", "/v1/iam/teams", boss, "")
	if find(list, "x") != nil {
		t.Errorf("refused create still wrote team x")
	}
}

// Another tenant cannot see, reach, change, or remove acme's team: every
// address of it misses and the row is untouched.
func TestTeams_AnotherTenantCannotReachTheTeam(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "acme/boss")
	mallory := h.token(t, "other/mallory")

	if code, _ := h.do(t, "POST", "/v1/iam/teams", boss,
		`{"name":"eng","displayName":"Engineering","users":["alice"]}`); code != 200 {
		t.Fatalf("create = %d, want 200", code)
	}

	// List is scoped to the caller's own organization.
	code, list := h.do(t, "GET", "/v1/iam/teams", mallory, "")
	if code != 200 {
		t.Fatalf("mallory list = %d, want 200", code)
	}
	if find(list, "eng") != nil {
		t.Errorf("another tenant's list contains acme's team: %v", list)
	}

	// Same name in another organization is a different team; addressing
	// "eng" as mallory misses acme's row.
	if code, _ := h.do(t, "GET", "/v1/iam/teams/eng", mallory, ""); code != 404 {
		t.Errorf("mallory get eng = %d, want 404", code)
	}
	if code, _ := h.do(t, "PUT", "/v1/iam/teams/eng", mallory,
		`{"name":"eng","displayName":"hijacked"}`); code != 404 {
		t.Errorf("mallory update eng = %d, want 404", code)
	}
	if code, _ := h.do(t, "DELETE", "/v1/iam/teams/eng", mallory, ""); code != 404 {
		t.Errorf("mallory delete eng = %d, want 404", code)
	}

	// Untouched.
	code, got := h.do(t, "GET", "/v1/iam/teams/eng", boss, "")
	if code != 200 {
		t.Fatalf("boss get eng after cross-tenant attempts = %d, want 200", code)
	}
	team := find(got, "eng")
	if team == nil {
		team = got
	}
	if d, _ := team["displayName"].(string); d != "Engineering" {
		t.Errorf("displayName = %v after cross-tenant update attempt, want Engineering", team["displayName"])
	}
}

// An update changes content only: the name, the created stamp, and the owning
// organization do not move.
func TestTeams_UpdateCannotMoveIdentity(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "acme/boss")

	if code, _ := h.do(t, "POST", "/v1/iam/teams", boss,
		`{"name":"eng","displayName":"Engineering","users":["alice"]}`); code != 200 {
		t.Fatalf("create = %d, want 200", code)
	}
	_, before := h.do(t, "GET", "/v1/iam/teams/eng", boss, "")
	b := find(before, "eng")
	if b == nil {
		b = before
	}
	created, _ := b["createdTime"].(string)
	owner, _ := b["owner"].(string)

	// The body tries to rename, restamp, and re-home the team.
	if code, _ := h.do(t, "PUT", "/v1/iam/teams/eng", boss,
		`{"name":"renamed","createdTime":"1999-01-01T00:00:00Z","organization":"other","displayName":"Platform","users":["alice"]}`); code != 200 {
		t.Fatalf("update = %d, want 200", code)
	}

	_, after := h.do(t, "GET", "/v1/iam/teams/eng", boss, "")
	a := find(after, "eng")
	if a == nil {
		a = after
	}
	if n, _ := a["name"].(string); n != "eng" {
		t.Errorf("name = %v after update, want eng", a["name"])
	}
	if c, _ := a["createdTime"].(string); c != created {
		t.Errorf("createdTime = %v after update, want %v", a["createdTime"], created)
	}
	if o, _ := a["owner"].(string); o != owner {
		t.Errorf("owner = %v after update, want %v", a["owner"], owner)
	}
	// And the attempted rename addressed nothing.
	if code, _ := h.do(t, "GET", "/v1/iam/teams/renamed", boss, ""); code != 404 {
		t.Errorf("get renamed = %d, want 404", code)
	}
}
