package phone

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

// figure is one captcha figure: a top and bottom fill drawn as two stacked
// rectangles, exactly how the vendor renders them.
type figure struct {
	top, bottom color.RGBA
	x, y        int
}

// TestMain removes the retry backoff so the retry tests stay fast.
func TestMain(m *testing.M) {
	webLoginRetryDelay = 0
	os.Exit(m.Run())
}

func rgba(name string) color.RGBA {
	for _, p := range captchaPalette {
		if p.name == name {
			return color.RGBA{uint8(p.r), uint8(p.g), uint8(p.b), 255}
		}
	}
	panic("unknown palette colour " + name)
}

// drawFigure paints a figure centred at (x, y) with a half-height of 15 and a
// half-width of 15, so its two colour centroids average to the centre.
func drawFigure(img *image.RGBA, f figure) {
	for dy := -15; dy < 15; dy++ {
		for dx := -15; dx < 15; dx++ {
			c := f.top
			if dy >= 0 {
				c = f.bottom
			}
			img.Set(f.x+dx, f.y+dy, c)
		}
	}
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

// buildOrderImage lays four figures left to right in the hint image.
func buildOrderImage(t *testing.T, figs []figure) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 156, 40))
	for i, f := range figs {
		centreX := 20 + i*39
		for dy := -14; dy < 14; dy++ {
			for dx := -14; dx < 14; dx++ {
				c := f.top
				if dy >= 0 {
					c = f.bottom
				}
				img.Set(centreX+dx, 20+dy, c)
			}
		}
	}
	return encodePNG(t, img)
}

// buildClickImage places four figures on a photographic-ish background.
func buildClickImage(t *testing.T, figs []figure) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 240, 200))
	// A blue background the classifier must reject.
	for y := range 200 {
		for x := range 240 {
			img.Set(x, y, color.RGBA{96, 192, 224, 255})
		}
	}
	for _, f := range figs {
		drawFigure(img, f)
	}
	return encodePNG(t, img)
}

// captchaFigures returns four figures whose top/bottom colours match the palette.
func captchaFigures() []figure {
	return []figure{
		{rgba("red"), rgba("green"), 175, 58},
		{rgba("blue"), rgba("yellow"), 56, 149},
		{rgba("magenta"), rgba("cyan"), 57, 59},
		{rgba("orange"), rgba("purple"), 174, 147},
	}
}

func TestSolveHaozhumaCaptcha(t *testing.T) {
	figs := captchaFigures()
	order := buildOrderImage(t, figs)
	click := buildClickImage(t, figs)

	points, errSolve := solveHaozhumaCaptcha(order, click)
	if errSolve != nil {
		t.Fatalf("solve: %v", errSolve)
	}
	if len(points) != 4 {
		t.Fatalf("got %d points, want 4", len(points))
	}
	// The hint names the figures in the same order they were laid out, so the
	// clicks must come back in that order.
	want := []captchaPoint{{175, 58}, {56, 149}, {57, 59}, {174, 147}}
	for i, got := range points {
		if abs(got.X-want[i].X) > 3 || abs(got.Y-want[i].Y) > 3 {
			t.Errorf("point %d = (%d,%d), want (%d,%d)±3", i, got.X, got.Y, want[i].X, want[i].Y)
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// buildClickImageWithDistractor paints the figures over a background that also
// holds a large patch of a palette colour, standing in for the vendor's marble
// backgrounds. The patch must not be mistaken for a figure or steal a figure's
// other half.
func buildClickImageWithDistractor(t *testing.T, figs []figure) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 240, 200))
	for y := range 200 {
		for x := range 240 {
			img.Set(x, y, color.RGBA{96, 192, 224, 255})
		}
	}
	// A blue swirl well away from every figure, larger than any figure.
	for y := range 20 {
		for x := 100; x < 200; x++ {
			img.Set(x, y, color.RGBA{0, 0, 255, 255})
		}
	}
	for _, f := range figs {
		drawFigure(img, f)
	}
	return encodePNG(t, img)
}

func TestSolveHaozhumaCaptchaIgnoresDistractorBackground(t *testing.T) {
	figs := captchaFigures()
	points, errSolve := solveHaozhumaCaptcha(buildOrderImage(t, figs), buildClickImageWithDistractor(t, figs))
	if errSolve != nil {
		t.Fatalf("solve: %v", errSolve)
	}
	want := []captchaPoint{{175, 58}, {56, 149}, {57, 59}, {174, 147}}
	if len(points) != len(want) {
		t.Fatalf("got %d points, want %d", len(points), len(want))
	}
	for i, got := range points {
		if abs(got.X-want[i].X) > 3 || abs(got.Y-want[i].Y) > 3 {
			t.Errorf("point %d = (%d,%d), want (%d,%d)±3", i, got.X, got.Y, want[i].X, want[i].Y)
		}
	}
}

// captchaServer stands in for the vendor's web surface.
type captchaServer struct {
	order      []byte
	click      []byte
	loginCalls atomic.Int32
	// captchaCalls counts how many captchas were served.
	captchaCalls atomic.Int32
	// rejectCaptcha makes the login endpoint answer a captcha error, and
	// rejectPassword makes it answer a credential error.
	rejectCaptcha  bool
	rejectPassword bool
	// emptyClick serves a click image with no figures, so solving fails.
	emptyClick bool
	// rejectSession accepts the sign-in but rejects the token when it is used,
	// which is how a stale or half-issued session shows up.
	rejectSession bool
	channels      string
}

func (s *captchaServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/captcha", func(w http.ResponseWriter, _ *http.Request) {
		s.captchaCalls.Add(1)
		click := s.click
		if s.emptyClick {
			blank := image.NewRGBA(image.Rect(0, 0, 240, 200))
			for y := range 200 {
				for x := range 240 {
					blank.Set(x, y, color.RGBA{96, 192, 224, 255})
				}
			}
			click = encodePNG(t, blank)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    0,
			"message": "ok",
			"data": map[string]any{
				"captchaId": "captcha_test",
				"image":     base64.StdEncoding.EncodeToString(click),
				"order":     base64.StdEncoding.EncodeToString(s.order),
			},
		})
	})
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		s.loginCalls.Add(1)
		switch {
		case s.rejectCaptcha:
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 100900, "message": "验证码不通过，请按顺序点击准确位置", "data": map[string]any{}})
		case s.rejectPassword:
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 100200, "message": "账号或密码错误", "data": map[string]any{}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    0,
				"message": "ok",
				"data":    map[string]any{"token": "session-abc", "expiresAt": "2026-11-26T00:00:00.000+08:00"},
			})
		}
	})
	mux.HandleFunc("/bindings", func(w http.ResponseWriter, r *http.Request) {
		if s.rejectSession || r.Header.Get("Authorization") != "Bearer session-abc" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 401, "message": "Unauthorized", "data": map[string]any{}})
			return
		}
		_, _ = w.Write([]byte(s.channels))
	})
	return httptest.NewServer(mux)
}

func newTestProvider(t *testing.T, baseURL string) *Haozhuma {
	t.Helper()
	provider, errProvider := NewHaozhuma(HaozhumaSecret{
		User: "api-user", Pass: "api-pass", WebBase: baseURL,
	}, nil)
	if errProvider != nil {
		t.Fatalf("new provider: %v", errProvider)
	}
	return provider
}

func TestWebLoginSucceeds(t *testing.T) {
	figs := captchaFigures()
	server := &captchaServer{
		order:    buildOrderImage(t, figs),
		click:    buildClickImage(t, figs),
		channels: `{"code":0,"message":"ok","data":{"list":[{"code":"21614-u1","projectId":"21614","projectName":"讯飞","price":"0.13","available":19,"status":"joined"}],"total":1,"page":1,"size":100}}`,
	}
	httpServer := server.start(t)
	defer httpServer.Close()

	provider := newTestProvider(t, httpServer.URL)
	result, errLogin := provider.WebLogin(context.Background(), "linhua888", "web-pass")
	if errLogin != nil {
		t.Fatalf("web login: %v", errLogin)
	}
	if result.Token != "session-abc" {
		t.Fatalf("token = %q", result.Token)
	}
	if result.Channels != 1 {
		t.Fatalf("channels = %d, want 1", result.Channels)
	}
}

// A session the server hands out but then refuses is a request problem, not a
// platform failure: the operator signs in again instead of reporting an outage.
func TestWebLoginRejectedSessionIsCredentialError(t *testing.T) {
	figs := captchaFigures()
	server := &captchaServer{
		order:         buildOrderImage(t, figs),
		click:         buildClickImage(t, figs),
		rejectSession: true,
	}
	httpServer := server.start(t)
	defer httpServer.Close()

	provider := newTestProvider(t, httpServer.URL)
	if _, errLogin := provider.WebLogin(context.Background(), "linhua888", "web-pass"); !errors.Is(errLogin, ErrCredential) {
		t.Fatalf("err = %v, want ErrCredential", errLogin)
	}
}

func TestWebLoginRetriesCaptchaButNotPassword(t *testing.T) {
	figs := captchaFigures()
	order, click := buildOrderImage(t, figs), buildClickImage(t, figs)

	captchaFail := &captchaServer{order: order, click: click, rejectCaptcha: true}
	captchaHTTP := captchaFail.start(t)
	defer captchaHTTP.Close()
	if _, errLogin := newTestProvider(t, captchaHTTP.URL).WebLogin(context.Background(), "u", "p"); errLogin == nil {
		t.Fatal("expected a captcha failure")
	}
	if calls := captchaFail.loginCalls.Load(); calls != haozhumaLoginAttempts {
		t.Fatalf("captcha failures made %d login calls, want %d retries", calls, haozhumaLoginAttempts)
	}

	passwordFail := &captchaServer{order: order, click: click, rejectPassword: true}
	passwordHTTP := passwordFail.start(t)
	defer passwordHTTP.Close()
	if _, errLogin := newTestProvider(t, passwordHTTP.URL).WebLogin(context.Background(), "u", "p"); errLogin == nil {
		t.Fatal("expected a credential failure")
	}
	if calls := passwordFail.loginCalls.Load(); calls != 1 {
		t.Fatalf("a bad password made %d login calls, want exactly 1", calls)
	}
}

func TestWebLoginRequiresCredentials(t *testing.T) {
	provider := newTestProvider(t, "http://127.0.0.1:0")
	if _, errLogin := provider.WebLogin(context.Background(), "", ""); errLogin == nil {
		t.Fatal("expected a missing-credential error")
	}
}

func TestWebLoginRetriesSolveFailure(t *testing.T) {
	figs := captchaFigures()
	server := &captchaServer{order: buildOrderImage(t, figs), emptyClick: true}
	httpServer := server.start(t)
	defer httpServer.Close()

	if _, errLogin := newTestProvider(t, httpServer.URL).WebLogin(context.Background(), "u", "p"); errLogin == nil {
		t.Fatal("expected a solve failure")
	}
	if calls := server.captchaCalls.Load(); calls != haozhumaLoginAttempts {
		t.Fatalf("solve failures fetched %d captchas, want %d", calls, haozhumaLoginAttempts)
	}
	if calls := server.loginCalls.Load(); calls != 0 {
		t.Fatalf("a solve failure must not post credentials, got %d login calls", calls)
	}
}
