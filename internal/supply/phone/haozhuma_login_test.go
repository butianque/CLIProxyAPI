package phone

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	// rejectCaptcha makes login.php answer a captcha error, and
	// rejectPassword makes it answer a credential error.
	rejectCaptcha  bool
	rejectPassword bool
	// emptyClick serves a click image with no figures, so solving fails.
	emptyClick bool
	channels   string
}

func (s *captchaServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/time.php", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","timestamp":1791575365,"token":"tok"}`))
	})
	mux.HandleFunc("/Verificationcode.php", func(w http.ResponseWriter, _ *http.Request) {
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
			"code":       1,
			"image_data": base64.StdEncoding.EncodeToString(click),
			"order":      base64.StdEncoding.EncodeToString(s.order),
			"captcha_id": "captcha_test",
		})
	})
	mux.HandleFunc("/login.php", func(w http.ResponseWriter, r *http.Request) {
		s.loginCalls.Add(1)
		switch {
		case s.rejectCaptcha:
			_ = json.NewEncoder(w).Encode(map[string]any{"code": -1, "msg": "验证不通过请重试，请点击准确的验证码位置"})
		case s.rejectPassword:
			_ = json.NewEncoder(w).Encode(map[string]any{"code": -1, "msg": "账号或密码错误"})
		default:
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "session-abc"})
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "msg": "登录成功"})
		}
	})
	mux.HandleFunc("/api.php", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Cookie"), "PHPSESSID=") {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "401", "msg": "请先登录"})
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
		channels: `{"code":"200","data":[{"uid":"u1","mc":"讯飞","yhj":"0.13","zxky":"可用数量:19","djzt":"已对接"}]}`,
	}
	httpServer := server.start(t)
	defer httpServer.Close()

	provider := newTestProvider(t, httpServer.URL)
	result, errLogin := provider.WebLogin(context.Background(), "linhua888", "web-pass")
	if errLogin != nil {
		t.Fatalf("web login: %v", errLogin)
	}
	if result.Cookie != "PHPSESSID=session-abc" {
		t.Fatalf("cookie = %q", result.Cookie)
	}
	if result.Channels != 1 {
		t.Fatalf("channels = %d, want 1", result.Channels)
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
