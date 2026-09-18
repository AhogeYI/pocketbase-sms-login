// SMS login flow tests against a real app: request (with RELAY_SMS_DEBUG=1
// the code echoes back for local verification), verify (token issued), and
// the abuse budget.
package authsms

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	// system-table migrations: PocketBase framework mode requires the app to
	// register them before bootstrap creates a fresh database.
	_ "github.com/pocketbase/pocketbase/migrations"
)

func newApp(t *testing.T) (http.Handler, func()) {
	t.Helper()
	t.Setenv("RELAY_SMS_DEBUG", "1")

	app := core.NewBaseApp(core.BaseAppConfig{
		DataDir:       t.TempDir(),
		EncryptionEnv: "authsms_test_env",
	})
	if err := app.Bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	app.Settings().Logs.MinLevel = 100

	// PocketBase seeds a default users auth collection on a fresh database;
	// the SMS identity only needs a phone text field on it.
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

func post(mux http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.7:55555"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestSMSRequestAndVerifyFullFlow(t *testing.T) {
	mux, cleanup := newApp(t)
	defer cleanup()

	phone := "13812345678"

	// A malformed number is rejected before anything else.
	if rec := post(mux, "/api/auth/sms/request", `{"phone":"12345"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad phone status = %d, want 400", rec.Code)
	}

	rec := post(mux, "/api/auth/sms/request", `{"phone":"`+phone+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("request status = %d body = %s", rec.Code, rec.Body.String())
	}
	var issued struct {
		Sent      bool   `json:"sent"`
		DebugCode string `json:"debug_code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !issued.Sent || len(issued.DebugCode) != 6 {
		t.Fatalf("unexpected request response: %s", rec.Body.String())
	}

	rec = post(mux, "/api/auth/sms/verify",
		`{"phone":"`+phone+`","code":"`+issued.DebugCode+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body = %s", rec.Code, rec.Body.String())
	}
	var auth struct {
		Token  string `json:"token"`
		Record struct {
			ID    string `json:"id"`
			Phone string `json:"phone"`
		} `json:"record"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auth); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if auth.Token == "" || auth.Record.ID == "" || auth.Record.Phone != phone {
		t.Fatalf("auth response incomplete: %s", rec.Body.String())
	}

	// The OTP is consumed: the same code cannot log in again.
	rec = post(mux, "/api/auth/sms/verify",
		`{"phone":"`+phone+`","code":"`+issued.DebugCode+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("replayed code status = %d, want 400", rec.Code)
	}

	// A second round for the same phone logs into the SAME account.
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
		t.Fatalf("second verify status = %d body = %s", rec.Code, rec.Body.String())
	}
	var second struct {
		Record struct {
			ID string `json:"id"`
		} `json:"record"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &second)
	if second.Record.ID != auth.Record.ID {
		t.Errorf("second login created a new account: %s != %s", second.Record.ID, auth.Record.ID)
	}
}

func TestSMSVerifyRejectsWrongCode(t *testing.T) {
	mux, cleanup := newApp(t)
	defer cleanup()

	phone := "13987654321"
	if rec := post(mux, "/api/auth/sms/request", `{"phone":"`+phone+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("request status = %d", rec.Code)
	}

	if rec := post(mux, "/api/auth/sms/verify", `{"phone":"`+phone+`","code":"000000"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("wrong code status = %d, want 400", rec.Code)
	}
	// Verify for a phone that never requested a code.
	if rec := post(mux, "/api/auth/sms/verify", `{"phone":"13711112222","code":"123456"}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown phone status = %d, want 404", rec.Code)
	}
}

func TestSMSRequestRateLimited(t *testing.T) {
	mux, cleanup := newApp(t)
	defer cleanup()

	phone := "13655556666"
	// per-phone budget is 3 per window; the 4th request must be throttled.
	for i := 0; i < 3; i++ {
		if rec := post(mux, "/api/auth/sms/request", `{"phone":"`+phone+`"}`); rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d", i, rec.Code)
		}
	}
	if rec := post(mux, "/api/auth/sms/request", `{"phone":"`+phone+`"}`); rec.Code != http.StatusTooManyRequests {
		t.Errorf("over-budget request status = %d, want 429", rec.Code)
	}

	// A different phone from the same IP still works until the IP budget
	// kicks in (15/window).
	ok := 0
	for i := 0; i < 12; i++ {
		p := "135000" + strings.Repeat("0", 0) + string(rune('0'+i%10)) + "0000"
		if len(p) != 11 {
			continue
		}
		if rec := post(mux, "/api/auth/sms/request", `{"phone":"`+p+`"}`); rec.Code == http.StatusOK {
			ok++
		} else if i == 0 {
			t.Logf("first other-number reply: %d %s", rec.Code, rec.Body.String())
		}
	}
	if ok == 0 {
		t.Error("IP budget choked other numbers entirely")
	}
}
