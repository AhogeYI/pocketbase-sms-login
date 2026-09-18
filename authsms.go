// Package authsms implements phone-number one-time-code login for
// PocketBase: two mounted routes, a pluggable SMS gateway, and layered
// anti-abuse budgets.
//
//	POST /api/auth/sms/request  {"phone":"138…"}   → creates (or reuses) the
//	                                               user, issues a 6-digit OTP
//	POST /api/auth/sms/verify   {"phone","code"}   → standard auth response
//
// Delivery: the SmsProvider interface is where the production gateway
// (Aliyun/Tencent SMS) plugs in via SetProvider. Without a provider the
// routes are mounted only when RELAY_SMS_DEBUG=1 explicitly opts into DEV
// mode (code written to the log and echoed as debug_code for local
// end-to-end testing); otherwise the routes stay unmounted — DEV delivery
// must never run in production by accident.
package authsms

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pocketbase/pocketbase/tools/types"
)

// otpTTL is how long a issued code stays valid (PB's own OTP default is 5m
// and its cleanup reaps used/expired rows).
const otpTTL = 5 * time.Minute

// maxAttemptsPerOTP is the verify attempt budget per issued code: after this
// many failures the OTP is destroyed, so brute-forcing the 10^6 code space
// within the TTL window is hopeless (a locked-out user just requests a new
// code — subject to the request budget).
const maxAttemptsPerOTP = 5

// limiterMaxKeys is the size ceiling of the limiter map; reaching it sweeps
// the entries whose window already passed (the map must not grow without
// bound over the process lifetime — keys are "every phone/IP ever seen").
const limiterMaxKeys = 8192

// Verify budgets: more headroom than /request (legitimate users mistype),
// still far below what a guessing attack needs.
const (
	verifyPerPhone = 10
	verifyPerIP    = 30
)

// phonePattern is the mainland-China mobile format — the only audience the
// SMS gateway will serve.
var phonePattern = regexp.MustCompile(`^1[3-9]\d{9}$`)

// provider is where the production SMS gateway (Aliyun/Tencent) plugs in via
// SetProvider. nil means DEV delivery — which additionally requires an
// explicit RELAY_SMS_DEBUG=1 opt-in or the routes stay unmounted.
var provider SmsProvider

// SetProvider registers the production SMS gateway. Call before Register.
func SetProvider(p SmsProvider) { provider = p }

// SmsProvider delivers one code to one phone number. The production
// implementation (Aliyun / Tencent) arrives with credentials; nil provider =
// DEV mode (log only).
type SmsProvider interface {
	Send(phone, code string) error
}

type limiterEntry struct {
	windowStart time.Time
	count       int
}

// rateLimiter is the process-local anti-abuse budget:
//
//	per phone: perPhone requests per window
//	per IP:    perIP requests per window
type rateLimiter struct {
	mu       sync.Mutex
	byKey    map[string]*limiterEntry
	window   time.Duration
	perPhone int
	perIP    int
}

func newRateLimiter(perPhone, perIP int) *rateLimiter {
	return &rateLimiter{
		byKey:    map[string]*limiterEntry{},
		window:   10 * time.Minute,
		perPhone: perPhone,
		perIP:    perIP,
	}
}

func (l *rateLimiter) allow(phone, ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.budgetLocked("p:"+phone, l.perPhone, now) {
		return false
	}
	return l.budgetLocked("i:"+ip, l.perIP, now)
}

// budget is the lock-holding entry point for single-key budgets (the
// per-OTP attempt counter). Callers inside allow() must use budgetLocked —
// sync.Mutex is not reentrant.
func (l *rateLimiter) budget(key string, max int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.budgetLocked(key, max, now)
}

func (l *rateLimiter) budgetLocked(key string, max int, now time.Time) bool {
	if len(l.byKey) >= limiterMaxKeys {
		l.pruneLocked(now)
	}
	entry, ok := l.byKey[key]
	if !ok || now.Sub(entry.windowStart) >= l.window {
		l.byKey[key] = &limiterEntry{windowStart: now, count: 1}
		return true
	}
	entry.count++
	return entry.count <= max
}

// pruneLocked drops the entries whose window has passed. Caller holds mu.
func (l *rateLimiter) pruneLocked(now time.Time) {
	for key, entry := range l.byKey {
		if now.Sub(entry.windowStart) >= l.window {
			delete(l.byKey, key)
		}
	}
}

// Register mounts the two routes on the serve router — but only when a
// delivery path actually exists: a registered provider, or the explicit
// RELAY_SMS_DEBUG=1 DEV opt-in. A provider-less build without the opt-in
// stays dark: no routes, no codes in logs (fail-closed).
func Register(app core.App) {
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		dev := provider == nil
		if dev && os.Getenv("RELAY_SMS_DEBUG") != "1" {
			app.Logger().Warn("[authsms] no SmsProvider and RELAY_SMS_DEBUG != 1 — " +
				"SMS login routes disabled (set RELAY_SMS_DEBUG=1 for local dev)")
			return e.Next()
		}

		reqLimiter := newRateLimiter(3, 15) // 3 codes / 10min per number, 15 / IP
		verifyLimiter := newRateLimiter(verifyPerPhone, verifyPerIP)

		sms := e.Router.Group("/api/auth/sms")
		sms.POST("/request", func(e *core.RequestEvent) error {
			return handleRequest(e, reqLimiter, provider, dev)
		})
		sms.POST("/verify", func(e *core.RequestEvent) error {
			return handleVerify(e, verifyLimiter)
		})
		app.Logger().Info("[authsms] sms login routes registered",
			slog.Bool("dev_mode", dev))
		return e.Next()
	})
}

func handleRequest(e *core.RequestEvent, limiter *rateLimiter, provider SmsProvider, dev bool) error {
	var body struct {
		Phone string `json:"phone"`
	}
	if err := e.BindBody(&body); err != nil {
		return e.BadRequestError("Invalid request body.", err)
	}
	phone := strings.TrimSpace(body.Phone)
	if !phonePattern.MatchString(phone) {
		return e.BadRequestError("Invalid phone number.", nil)
	}
	if !limiter.allow(phone, e.RealIP(), time.Now()) {
		return e.TooManyRequestsError("Too many code requests, try later.", nil)
	}

	user, err := findOrCreateUser(e.App, phone)
	if err != nil {
		return e.InternalServerError("Failed to provision the account.", err)
	}

	code := security.RandomStringWithAlphabet(6, "1234567890")
	otp := core.NewOTP(e.App)
	otp.SetRecordRef(user.Id)
	otp.SetCollectionRef(user.Collection().Id)
	otp.SetSentTo(phone)
	otp.SetPassword(code)
	if err := e.App.Save(otp); err != nil {
		return e.InternalServerError("Failed to issue the code.", err)
	}

	if provider != nil {
		// Production delivery: the code goes to the gateway, never to logs
		// or responses.
		if err := provider.Send(phone, code); err != nil {
			e.App.Logger().Error("[authsms] provider send failed", slog.String("error", err.Error()))
			return e.InternalServerError("Failed to deliver the code.", err)
		}
	} else {
		// DEV delivery: the code lands in the log. Reachable only with the
		// RELAY_SMS_DEBUG=1 opt-in (see Register).
		e.App.Logger().Info("[authsms] dev-mode code issued",
			slog.String("phone", maskPhone(phone)), slog.String("code", code))
	}

	response := map[string]any{"sent": true}
	if dev {
		response["debug_code"] = code
	}
	return e.JSON(http.StatusOK, response)
}

func handleVerify(e *core.RequestEvent, limiter *rateLimiter) error {
	var body struct {
		Phone string `json:"phone"`
		Code  string `json:"code"`
	}
	if err := e.BindBody(&body); err != nil {
		return e.BadRequestError("Invalid request body.", err)
	}
	phone := strings.TrimSpace(body.Phone)
	code := strings.TrimSpace(body.Code)
	if !phonePattern.MatchString(phone) || code == "" {
		return e.BadRequestError("Invalid request.", nil)
	}

	// The verify endpoint carries its own budgets — it is a custom route and
	// does not inherit PB's auth-endpoint rate limits. Without this, the
	// 10^6 code space is guessable within the 5-minute TTL.
	now := time.Now()
	if !limiter.allow(phone, e.RealIP(), now) {
		return e.TooManyRequestsError("Too many verification attempts, try later.", nil)
	}

	user, err := e.App.FindFirstRecordByFilter("users", "phone = {:phone}",
		map[string]any{"phone": phone})
	if err != nil {
		return e.NotFoundError("No account for this phone number.", nil)
	}

	otps, err := e.App.FindRecordsByFilter(core.CollectionNameOTPs,
		"recordRef = {:uid} && sentTo = {:phone}", "-created", 1, 0,
		map[string]any{"uid": user.Id, "phone": phone})
	if err != nil || len(otps) == 0 {
		return e.BadRequestError("Invalid or expired code.", nil)
	}
	otp := otps[0]
	if issued, err := types.ParseDateTime(otp.GetString("created")); err != nil ||
		time.Since(issued.Time()) > otpTTL {
		return e.BadRequestError("Invalid or expired code.", nil)
	}
	// Per-code attempt budget: every verify attempt (including this one)
	// counts; exhausting it destroys the OTP so even the correct code is
	// dead and the guessing game ends.
	if !limiter.budget("o:"+otp.Id, maxAttemptsPerOTP, now) {
		if err := e.App.Delete(otp); err != nil {
			return e.InternalServerError("Failed to consume the code.", err)
		}
		return e.BadRequestError("Invalid or expired code.", nil)
	}
	if !otp.ValidatePassword(code) {
		return e.BadRequestError("Invalid or expired code.", nil)
	}
	// Consume like PocketBase's own auth-with-otp does: delete the OTP so a
	// replayed code finds nothing to match.
	if err := e.App.Delete(otp); err != nil {
		return e.InternalServerError("Failed to consume the code.", err)
	}
	return apis.RecordAuthResponse(e, user, "sms", nil)
}

// findOrCreateUser resolves the account behind a phone number. New accounts
// get a reserved placeholder e-mail (unique, clearly non-deliverable) and an
// unguessable random password — the phone OTP is their only login.
func findOrCreateUser(app core.App, phone string) (*core.Record, error) {
	if existing, err := app.FindFirstRecordByFilter("users", "phone = {:phone}",
		map[string]any{"phone": phone}); err == nil {
		return existing, nil
	}

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		return nil, fmt.Errorf("users collection: %w", err)
	}
	user := core.NewRecord(users)
	user.Set("email", "sms-"+phone+"@otp.invalid")
	user.Set("username", "sms"+phone) // unique across SMS accounts (14 chars)
	user.Set("phone", phone)
	user.SetVerified(true)
	user.SetPassword(security.RandomString(32))
	if err := app.Save(user); err != nil {
		return nil, err
	}
	return user, nil
}

func maskPhone(phone string) string {
	if len(phone) != 11 {
		return phone
	}
	return phone[:3] + "****" + phone[7:]
}
