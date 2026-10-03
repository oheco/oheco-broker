package control

import (
	"path/filepath"
	"testing"
)

func assertRegistrationSettings(t *testing.T, settings map[string]any, policy string, relay bool) {
	t.Helper()
	if settings["registration_policy"] != policy || settings["registration_relay_enabled"] != relay {
		t.Fatalf("registration settings = %v, want policy=%s relay=%t", settings, policy, relay)
	}
}

func TestRegistrationRelayDefaultsAndApproval(t *testing.T) {
	t.Run("compatible default", func(t *testing.T) {
		s := apiFixture(t, Config{})
		assertRegistrationSettings(t, apiCall(t, s, "GET", "/v1/admin/settings", fixtureAdmin, nil, 200), "open", false)
		_, account := fixtureRegister(t, s, "default-relay")
		capabilities := apiCall(t, s, "GET", "/v1/me/capabilities", account, nil, 200)
		if capabilities["status"] != "active" || capabilities["relay_enabled"] != false {
			t.Fatalf("default registration capabilities = %v", capabilities)
		}
	})

	t.Run("open immediately active with relay", func(t *testing.T) {
		s := apiFixture(t, Config{RegistrationRelayEnabled: true, TURN: TURNConfig{Enabled: true, ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", AllowLoopbackPeers: true}})
		assertRegistrationSettings(t, apiCall(t, s, "GET", "/v1/admin/settings", fixtureAdmin, nil, 200), "open", true)
		registered := apiCall(t, s, "POST", "/v1/tenants/register", "", map[string]any{"name": "open-relay", "password": fixturePassword}, 201)
		tenant := registered["tenant"].(map[string]any)
		if tenant["status"] != "active" || tenant["relay_enabled"] != true {
			t.Fatalf("open registration tenant = %v", tenant)
		}
		account := registered["token"].(string)
		capabilities := apiCall(t, s, "GET", "/v1/me/capabilities", account, nil, 200)
		if capabilities["status"] != "active" || capabilities["relay_enabled"] != true || capabilities["turn_available"] != true {
			t.Fatalf("open registration capabilities = %v", capabilities)
		}
		broker, device := fixtureBroker(t, s, account, "host")
		created := apiCall(t, s, "POST", "/v1/sessions", account, map[string]any{"broker_id": broker, "relay_mode": "force"}, 201)
		sid, session := created["session_id"].(string), created["session_token"].(string)
		apiCall(t, s, "POST", "/v1/sessions/"+sid+"/approve", device, map[string]any{"peer_authenticated": true, "relay": true}, 200)
		apiCall(t, s, "POST", "/v1/sessions/"+sid+"/turn", session, nil, 200)
		if !s.authorizeTURN(tenant["id"].(string), broker, sid) {
			t.Fatal("new open registration cannot authorize TURN without an admin relay grant")
		}
	})

	t.Run("approval remains pending with relay", func(t *testing.T) {
		s := apiFixture(t, Config{RegistrationPolicy: "approval", RegistrationRelayEnabled: true})
		registered := apiCall(t, s, "POST", "/v1/tenants/register", "", map[string]any{"name": "pending-relay", "password": fixturePassword}, 201)
		tenant := registered["tenant"].(map[string]any)
		if tenant["status"] != "pending" || tenant["relay_enabled"] != true {
			t.Fatalf("approval registration tenant = %v", tenant)
		}
		account := registered["token"].(string)
		capabilities := apiCall(t, s, "GET", "/v1/capabilities", account, nil, 200)
		if capabilities["status"] != "pending" || capabilities["relay_enabled"] != true {
			t.Fatalf("approval registration capabilities = %v", capabilities)
		}
		apiCall(t, s, "POST", "/v1/tenants/login", "", map[string]any{"name": "pending-relay", "password": fixturePassword}, 403)
		apiCall(t, s, "POST", "/v1/brokers", account, map[string]any{"name": "forbidden"}, 403)
		apiCall(t, s, "POST", "/v1/sessions", account, map[string]any{"broker_id": "absent", "relay_mode": "force"}, 403)
	})
}

func TestRegistrationSettingsPATCHAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "registration.sqlite")
	s := apiFixture(t, Config{DBPath: path, RegistrationPolicy: "closed"})
	assertRegistrationSettings(t, apiCall(t, s, "GET", "/v1/admin/settings", fixtureAdmin, nil, 200), "closed", false)
	patched := apiCall(t, s, "PATCH", "/v1/admin/settings", fixtureAdmin, map[string]any{"registration_policy": "approval", "registration_relay_enabled": true}, 200)
	assertRegistrationSettings(t, patched, "approval", true)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := apiFixture(t, Config{DBPath: path, RegistrationPolicy: "open", RegistrationRelayEnabled: false})
	assertRegistrationSettings(t, apiCall(t, reopened, "GET", "/v1/admin/settings", fixtureAdmin, nil, 200), "approval", true)
	registered := apiCall(t, reopened, "POST", "/v1/tenants/register", "", map[string]any{"name": "persisted-relay", "password": fixturePassword}, 201)
	tenant := registered["tenant"].(map[string]any)
	if tenant["status"] != "pending" || tenant["relay_enabled"] != true {
		t.Fatalf("persisted registration defaults = %v", tenant)
	}

	patched = apiCall(t, reopened, "PATCH", "/v1/admin/settings", fixtureAdmin, map[string]any{"registration_relay_enabled": false}, 200)
	assertRegistrationSettings(t, patched, "approval", false)
	_, account := fixtureRegister(t, reopened, "relay-disabled-default")
	capabilities := apiCall(t, reopened, "GET", "/v1/capabilities", account, nil, 200)
	if capabilities["status"] != "pending" || capabilities["relay_enabled"] != false {
		t.Fatalf("independent false PATCH changed policy or failed new default: %v", capabilities)
	}
	previous := apiCall(t, reopened, "GET", "/v1/me", registered["token"].(string), nil, 200)["tenant"].(map[string]any)
	if previous["relay_enabled"] != true {
		t.Fatal("registration default PATCH changed an existing tenant")
	}
	patched = apiCall(t, reopened, "PATCH", "/v1/admin/settings", fixtureAdmin, map[string]any{"registration_policy": "open"}, 200)
	assertRegistrationSettings(t, patched, "open", false)
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	again := apiFixture(t, Config{DBPath: path, RegistrationPolicy: "closed", RegistrationRelayEnabled: true})
	assertRegistrationSettings(t, apiCall(t, again, "GET", "/v1/admin/settings", fixtureAdmin, nil, 200), "open", false)
	_, account = fixtureRegister(t, again, "persisted-false")
	capabilities = apiCall(t, again, "GET", "/v1/capabilities", account, nil, 200)
	if capabilities["status"] != "active" || capabilities["relay_enabled"] != false {
		t.Fatalf("persisted false did not override startup true: %v", capabilities)
	}
}

func TestRegistrationRelayMigrationPreservesExistingPolicyAndTenants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "legacy.sqlite")
	s := apiFixture(t, Config{DBPath: path, RegistrationPolicy: "approval"})
	_, account := fixtureRegister(t, s, "legacy-tenant")
	// Removing only the new key models the settings layout before this option existed.
	if _, err := s.db.Exec("DELETE FROM settings WHERE key='registration_relay_enabled'"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := apiFixture(t, Config{DBPath: path, RegistrationPolicy: "open", RegistrationRelayEnabled: true})
	assertRegistrationSettings(t, apiCall(t, reopened, "GET", "/v1/admin/settings", fixtureAdmin, nil, 200), "approval", true)
	previous := apiCall(t, reopened, "GET", "/v1/me", account, nil, 200)["tenant"].(map[string]any)
	if previous["status"] != "pending" || previous["relay_enabled"] != false {
		t.Fatalf("migration changed existing tenant = %v", previous)
	}
	registered := apiCall(t, reopened, "POST", "/v1/tenants/register", "", map[string]any{"name": "after-migration", "password": fixturePassword}, 201)
	tenant := registered["tenant"].(map[string]any)
	if tenant["status"] != "pending" || tenant["relay_enabled"] != true {
		t.Fatalf("migration ignored initial default or persisted policy = %v", tenant)
	}
}

func TestRegistrationSettingsInvalidPATCHDoesNotPartiallyUpdate(t *testing.T) {
	s := apiFixture(t, Config{RegistrationPolicy: "approval", RegistrationRelayEnabled: true})
	for _, tc := range []struct {
		name string
		body any
	}{
		{"empty", map[string]any{}},
		{"missing body", nil},
		{"invalid policy", map[string]any{"registration_policy": "invalid", "registration_relay_enabled": false}},
		{"empty policy", map[string]any{"registration_policy": "", "registration_relay_enabled": false}},
		{"wrong policy type", map[string]any{"registration_policy": false, "registration_relay_enabled": false}},
		{"unknown field", map[string]any{"registration_policy": "closed", "registration_relay_enabled": false, "unknown": true}},
		{"string bool", map[string]any{"registration_policy": "closed", "registration_relay_enabled": "false"}},
		{"number bool", map[string]any{"registration_policy": "closed", "registration_relay_enabled": 0}},
		{"array bool", map[string]any{"registration_policy": "closed", "registration_relay_enabled": []any{false}}},
		{"null policy alone", map[string]any{"registration_policy": nil}},
		{"null bool alone", map[string]any{"registration_relay_enabled": nil}},
		{"null policy with valid bool", map[string]any{"registration_policy": nil, "registration_relay_enabled": false}},
		{"null bool with valid policy", map[string]any{"registration_policy": "closed", "registration_relay_enabled": nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apiCall(t, s, "PATCH", "/v1/admin/settings", fixtureAdmin, tc.body, 400)
			assertRegistrationSettings(t, apiCall(t, s, "GET", "/v1/admin/settings", fixtureAdmin, nil, 200), "approval", true)
		})
	}
	apiCall(t, s, "PATCH", "/v1/admin/settings", "", map[string]any{"registration_policy": "closed", "registration_relay_enabled": false}, 401)
	assertRegistrationSettings(t, apiCall(t, s, "GET", "/v1/admin/settings", fixtureAdmin, nil, 200), "approval", true)
}

func TestRegistrationSettingsPairPATCHRollsBackOnDatabaseError(t *testing.T) {
	s := apiFixture(t, Config{})
	// Fail the second UPDATE after the first succeeds, exercising the transaction rollback.
	if _, err := s.db.Exec(`CREATE TRIGGER reject_registration_relay BEFORE UPDATE OF value ON settings
		WHEN NEW.key='registration_relay_enabled' BEGIN SELECT RAISE(ABORT, 'injected settings failure'); END`); err != nil {
		t.Fatal(err)
	}
	apiCall(t, s, "PATCH", "/v1/admin/settings", fixtureAdmin, map[string]any{"registration_policy": "closed", "registration_relay_enabled": true}, 500)
	assertRegistrationSettings(t, apiCall(t, s, "GET", "/v1/admin/settings", fixtureAdmin, nil, 200), "open", false)
	if _, err := s.db.Exec("DROP TRIGGER reject_registration_relay"); err != nil {
		t.Fatal(err)
	}
	assertRegistrationSettings(t, apiCall(t, s, "PATCH", "/v1/admin/settings", fixtureAdmin, map[string]any{"registration_policy": "approval", "registration_relay_enabled": true}, 200), "approval", true)
}
