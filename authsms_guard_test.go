// Guard tests: DEV delivery must be opt-in (fail-closed without a provider),
// verify must carry an attempt budget that kills a battered OTP, and the
// process-local limiter map must not grow without bound.
package authsms

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	_ "github.com/pocketbase/pocketbase/migrations"
)

// newAppWithEnv boots the same stack as newApp but with an explicit
// RELAY_SMS_DEBUG value ("" = unset) so the fail-closed path is testable.
func newAppWithEnv(t *testing.T, debug string) (http.Handler, func()) {
	t.Helper()
	t.Setenv("RELAY_SMS_DEBUG", debug)

	app := core.NewBaseApp(core.BaseAppConfig{
		DataDir:       t.TempDir(),
		EncryptionEnv: "authsms_guard_test_env",
	})
	if err := app.Bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	app.Settings().Logs.MinLevel = 100

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatalf("users collection: %v", err)
	}
	if users.Fields.GetByName("phone") == nil {
		users.Fields.Add(&core.TextField{Name: "phone"})
		if err := app.Save(users); err != nil {
			t.Fatalf("add phone field: %v", err)
		}
	}

	Register(app)

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	serveEvent := &core.ServeEvent{App: app, Router: router, Server: &http.Server{}}
	var mux http.Handler
	if err := app.OnServe().Trigger(serveEvent, func(e *core.ServeEvent) error {
		built, err := e.Router.BuildMux()
		mux = built
		return err
	}); err != nil {
		t.Fatalf("serve trigger: %v", err)
	}

	return mux, func() {
		_ = app.ResetBootstrapState()
		_ = os.RemoveAll(app.DataDir())
	}
}

// Without an explicit DEV opt-in a provider-less build must not mount the
// SMS login routes at all — the code would otherwise be handed out in log
// plaintext on every deployment.
func TestSMSRoutesDisabledWithoutDevOptIn(t *testing.T) {
	mux, cleanup := newAppWithEnv(t, "")
	defer cleanup()

	rec := post(mux, "/api/auth/sms/request", `{"phone":"13812345678"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("request without DEV opt-in = %d body = %s, want 404 (routes not mounted)", rec.Code, rec.Body.String())
	}
	rec = post(mux, "/api/auth/sms/verify", `{"phone":"13812345678","code":"123456"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("verify without DEV opt-in = %d, want 404 (routes not mounted)", rec.Code)
	}
}

// The verify endpoint must carry an attempt budget: after maxAttemptsPerOTP
// failures the OTP is destroyed, so even the correct code is dead and
// guessing 10^6 combinations within the TTL window is hopeless.
func TestSMSVerifyAttemptBudgetKillsOTP(t *testing.T) {
	mux, cleanup := newApp(t)
	defer cleanup()

	phone := "13800138000"
	rec := post(mux, "/api/auth/sms/request", `{"phone":"`+phone+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("request status = %d", rec.Code)
	}
	var issued struct {
		DebugCode string `json:"debug_code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil || len(issued.DebugCode) != 6 {
		t.Fatalf("request response = %s", rec.Body.String())
	}

	for i := 0; i < maxAttemptsPerOTP; i++ {
		if rec := post(mux, "/api/auth/sms/verify",
			`{"phone":"`+phone+`","code":"00000`+fmt.Sprint(i%10)+`"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("wrong attempt %d status = %d, want 400", i, rec.Code)
		}
	}

	// Budget spent: the OTP is destroyed — the CORRECT code must not log in.
	rec = post(mux, "/api/auth/sms/verify",
		`{"phone":"`+phone+`","code":"`+issued.DebugCode+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("correct code after budget spent = %d body = %s, want 400", rec.Code, rec.Body.String())
	}

	// A fresh OTP (new request) works again.
	rec = post(mux, "/api/auth/sms/request", `{"phone":"`+phone+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("second request status = %d", rec.Code)
	}
	var again struct {
		DebugCode string `json:"debug_code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &again)
	rec = post(mux, "/api/auth/sms/verify",
		`{"phone":"`+phone+`","code":"`+again.DebugCode+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("fresh OTP verify = %d body = %s, want 200", rec.Code, rec.Body.String())
	}
}

func TestRateLimiterPrunesExpiredKeys(t *testing.T) {
	l := newRateLimiter(3, 15)
	now := time.Now()

	for i := 0; i < limiterMaxKeys; i++ {
		l.budget(fmt.Sprintf("k%d", i), 5, now.Add(-time.Hour))
	}
	if len(l.byKey) != limiterMaxKeys {
		t.Fatalf("setup: map size = %d, want %d", len(l.byKey), limiterMaxKeys)
	}

	// One more insert at a ceiling full of dead windows must sweep them,
	// not grow the map without bound.
	if !l.budget("fresh", 5, now) {
		t.Fatalf("fresh key rejected")
	}
	if len(l.byKey) > limiterMaxKeys {
		t.Errorf("map size = %d after prune, want <= %d", len(l.byKey), limiterMaxKeys)
	}
	if _, ok := l.byKey["k0"]; ok {
		t.Errorf("expired keys survived the prune")
	}
	if _, ok := l.byKey["fresh"]; !ok {
		t.Errorf("the triggering key was dropped")
	}
}

func TestRateLimiterPruneKeepsLiveWindows(t *testing.T) {
	l := newRateLimiter(3, 15)
	now := time.Now()

	// A live window mixed into a full map must survive the sweep.
	l.budget("live", 5, now.Add(-time.Minute))
	for i := 0; i < limiterMaxKeys; i++ {
		l.budget(fmt.Sprintf("dead%d", i), 5, now.Add(-2*time.Hour))
	}
	l.budget("trigger", 5, now)

	if _, ok := l.byKey["live"]; !ok {
		t.Errorf("live window was pruned")
	}
}
