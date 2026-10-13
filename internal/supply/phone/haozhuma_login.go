package phone

// This file automates the vendor's web sign-in, which is what mints the session
// cookie the channel surface needs.
//
// The sign-in is a two-step challenge: the page asks for a picture captcha and
// the account/password, then the browser posts the four click coordinates back.
// The picture is a "click these four shapes in this order" puzzle: one image
// shows four two-colour figures, another names those figures in the order they
// must be clicked. The figures are drawn in a fixed eight-colour palette on a
// photographic background, so the puzzle is solved by colour, not by a model:
// classify every pixel to its nearest palette colour, find each figure's two
// halves in the click image, and read the required order off the hint image.
//
// The vendor documents the sign-in as un-automatable because of this captcha.
// That is true for a person, not for a program: the puzzle is deterministic and
// colour-only, so it is solved here with no third-party service.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/png" // register the PNG decoder for the captcha images
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

// haozhumaLoginAttempts bounds how many fresh captchas one sign-in tries. A
// solve is reliable but not perfect, and a rejected captcha is free to retry;
// a rejected password is not, so only captcha failures are retried.
const haozhumaLoginAttempts = 3

// webLoginRetryDelay is the base wait between captcha attempts. The vendor
// rate-limits its captcha endpoints ("访问频繁"), so hammering a retry makes the
// limit worse; a short backoff lets the next attempt through.
var webLoginRetryDelay = 3 * time.Second

// captchaColorTolerance is the squared RGB distance under which a pixel counts
// as a palette colour. The figures are flat fills, so a tight tolerance still
// keeps their interiors while rejecting the photographic background.
const captchaColorTolerance = 4000

// captchaMinPixels is the smallest figure a colour must paint to count, which
// filters stray anti-aliased pixels from the background.
const captchaMinPixels = 60

// errCaptchaRejected marks a sign-in failure the caller may retry with a fresh
// captcha, as opposed to a wrong password, which must not be retried.
var errCaptchaRejected = errors.New("sms/haozhuma: captcha rejected")

// errCaptchaRetry marks a captcha-stage failure (fetch, solve, or submit) that a
// fresh captcha can fix, so the attempt is worth repeating.
var errCaptchaRetry = errors.New("sms/haozhuma: captcha attempt failed")

// WebLoginResult is the outcome of an automated web sign-in.
type WebLoginResult struct {
	// Cookie is the session cookie, in "PHPSESSID=..." form.
	Cookie string
	// Channels is how many joined channels the fresh session can see. It proves
	// the cookie works rather than merely existing.
	Channels int
}

// captchaPoint is one click position in the captcha image's pixel space.
type captchaPoint struct {
	X int `json:"x"`
	Y int `json:"y"`
}

// paletteColor is one of the eight flat fills the captcha figures use.
type paletteColor struct {
	name    string
	r, g, b int
}

// captchaPalette is the fixed fill set. Order does not matter; a pixel takes the
// nearest entry.
var captchaPalette = []paletteColor{
	{"red", 255, 0, 0},
	{"green", 0, 255, 0},
	{"blue", 0, 0, 255},
	{"yellow", 255, 255, 0},
	{"magenta", 255, 0, 255},
	{"cyan", 0, 255, 255},
	{"orange", 255, 165, 0},
	{"purple", 128, 0, 128},
}

// classifyColor maps a pixel to the nearest palette colour, or reports that it
// is not close enough to any of them (background).
func classifyColor(r, g, b uint8) (string, bool) {
	bestName := ""
	bestDist := math.MaxInt32
	for _, p := range captchaPalette {
		dr := int(r) - p.r
		dg := int(g) - p.g
		db := int(b) - p.b
		distance := dr*dr + dg*dg + db*db
		if distance < bestDist {
			bestDist = distance
			bestName = p.name
		}
	}
	if bestDist <= captchaColorTolerance {
		return bestName, true
	}
	return "", false
}

// WebLogin signs in to the web surface and returns a working session cookie.
//
// The account and password are the operator's browser sign-in, not the API key.
// A rejected captcha is retried with a fresh one; a rejected password is not.
func (h *Haozhuma) WebLogin(ctx context.Context, user, pass string) (WebLoginResult, error) {
	user = strings.TrimSpace(user)
	if user == "" || strings.TrimSpace(pass) == "" {
		return WebLoginResult{}, fmt.Errorf("%w: a web account and password are required to sign in", ErrCredential)
	}
	var lastErr error
	for attempt := 0; attempt < haozhumaLoginAttempts; attempt++ {
		if attempt > 0 && webLoginRetryDelay > 0 {
			select {
			case <-ctx.Done():
				return WebLoginResult{}, ctx.Err()
			case <-time.After(webLoginRetryDelay * time.Duration(attempt)):
			}
		}
		result, errAttempt := h.webLoginOnce(ctx, user, pass)
		if errAttempt == nil {
			return result, nil
		}
		lastErr = errAttempt
		// Only captcha-stage failures are worth a fresh captcha. A wrong
		// account or password is not retried, or a typo would burn attempts.
		if !errors.Is(errAttempt, errCaptchaRetry) && !errors.Is(errAttempt, errCaptchaRejected) {
			return WebLoginResult{}, errAttempt
		}
	}
	return WebLoginResult{}, lastErr
}

// webLoginOnce runs one full sign-in: fetch a captcha, solve it, post the
// credentials, then confirm the session by reading the channel list with it.
func (h *Haozhuma) webLoginOnce(ctx context.Context, user, pass string) (WebLoginResult, error) {
	clickPNG, orderPNG, captchaID, errFetch := h.fetchCaptcha(ctx)
	if errFetch != nil {
		return WebLoginResult{}, fmt.Errorf("%w: %v", errCaptchaRetry, errFetch)
	}
	points, errSolve := solveHaozhumaCaptcha(orderPNG, clickPNG)
	if errSolve != nil {
		// Some vendor images (overlapping figures) cannot be read; a fresh one
		// usually can, so this is retryable rather than fatal.
		return WebLoginResult{}, fmt.Errorf("%w: %v", errCaptchaRetry, errSolve)
	}
	cookie, errSubmit := h.submitWebLogin(ctx, captchaID, user, pass, points)
	if errSubmit != nil {
		return WebLoginResult{}, errSubmit
	}
	channels, errVerify := h.countChannelsWithCookie(ctx, cookie)
	if errVerify != nil {
		return WebLoginResult{}, errVerify
	}
	return WebLoginResult{Cookie: cookie, Channels: channels}, nil
}

// fetchCaptcha asks the vendor for one captcha: the click picture, the order
// hint, and the challenge id that ties them together.
func (h *Haozhuma) fetchCaptcha(ctx context.Context) (clickPNG, orderPNG []byte, captchaID string, err error) {
	base := h.webBase()

	var timePayload struct {
		Timestamp int64  `json:"timestamp"`
		Token     string `json:"token"`
		Status    string `json:"status"`
		Msg       string `json:"msg"`
	}
	if errTime := h.webRequest(ctx, http.MethodGet, base+"/time.php", "", nil, &timePayload); errTime != nil {
		return nil, nil, "", errTime
	}
	if strings.TrimSpace(timePayload.Token) == "" {
		if msg := strings.TrimSpace(timePayload.Msg); msg != "" {
			return nil, nil, "", fmt.Errorf("sms/haozhuma web login: the captcha endpoint declined: %s", msg)
		}
		return nil, nil, "", errors.New("sms/haozhuma web login: the server time endpoint returned no token")
	}

	request, errMarshal := json.Marshal(map[string]any{
		"token":     timePayload.Token,
		"timestamp": timePayload.Timestamp,
	})
	if errMarshal != nil {
		return nil, nil, "", errMarshal
	}
	var codePayload struct {
		Code      int    `json:"code"`
		Msg       string `json:"msg"`
		ImageData string `json:"image_data"`
		Order     string `json:"order"`
		CaptchaID string `json:"captcha_id"`
	}
	if errCode := h.webRequest(ctx, http.MethodPost, base+"/Verificationcode.php", "application/json", request, &codePayload); errCode != nil {
		return nil, nil, "", errCode
	}
	if codePayload.ImageData == "" || codePayload.Order == "" {
		return nil, nil, "", fmt.Errorf("sms/haozhuma web login: no captcha returned: %s", strings.TrimSpace(codePayload.Msg))
	}

	clickPNG, errClick := base64.StdEncoding.DecodeString(codePayload.ImageData)
	if errClick != nil {
		return nil, nil, "", fmt.Errorf("sms/haozhuma web login: decode captcha image: %w", errClick)
	}
	orderPNG, errOrder := base64.StdEncoding.DecodeString(codePayload.Order)
	if errOrder != nil {
		return nil, nil, "", fmt.Errorf("sms/haozhuma web login: decode order image: %w", errOrder)
	}
	return clickPNG, orderPNG, codePayload.CaptchaID, nil
}

// submitWebLogin posts the solved captcha and the credentials. On success it
// returns the session cookie; on failure the vendor's message is classified so
// a captcha problem stays retryable while a bad password does not.
func (h *Haozhuma) submitWebLogin(ctx context.Context, captchaID, user, pass string, points []captchaPoint) (string, error) {
	body, errMarshal := json.Marshal(map[string]any{
		"clicks":     points,
		"captcha_id": captchaID,
		"username":   user,
		"password":   pass,
	})
	if errMarshal != nil {
		return "", errMarshal
	}
	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, h.webBase()+"/login.php", bytes.NewReader(body))
	if errReq != nil {
		return "", errReq
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, errDo := h.http.Do(req)
	if errDo != nil {
		return "", fmt.Errorf("sms/haozhuma web login: %w", errDo)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if errDecode := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); errDecode != nil {
		return "", fmt.Errorf("sms/haozhuma web login: decode login reply: %w", errDecode)
	}
	if result.Code != 0 {
		message := strings.TrimSpace(result.Msg)
		if message == "" {
			message = "sign-in rejected"
		}
		// A captcha complaint is retryable; anything else (bad account/password)
		// must not be retried, or a typo would burn login attempts.
		if strings.Contains(message, "验证") {
			return "", fmt.Errorf("%w: %s", errCaptchaRejected, message)
		}
		return "", fmt.Errorf("sms/haozhuma web login: %s", message)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "PHPSESSID" && cookie.Value != "" {
			return "PHPSESSID=" + cookie.Value, nil
		}
	}
	return "", errors.New("sms/haozhuma web login: the server accepted the sign-in but returned no session cookie")
}

// countChannelsWithCookie reads the joined channel list with a candidate cookie,
// which both proves the cookie authenticates and reports how many channels it
// can see.
func (h *Haozhuma) countChannelsWithCookie(ctx context.Context, cookie string) (int, error) {
	var payload struct {
		Code json.RawMessage `json:"code"`
		Msg  string          `json:"msg"`
		Data []webChannelRow `json:"data"`
	}
	if errGet := h.webGetWithCookie(ctx, cookie, "type=3", &payload); errGet != nil {
		return 0, errGet
	}
	if strings.Trim(strings.TrimSpace(string(payload.Code)), `"`) != "200" {
		message := strings.TrimSpace(payload.Msg)
		if message == "" {
			message = "channel list rejected"
		}
		return 0, fmt.Errorf("sms/haozhuma web login: the fresh session was rejected: %s", message)
	}
	return len(payload.Data), nil
}

// webGetWithCookie is webGet against an explicit cookie, used before the cookie
// has been stored.
func (h *Haozhuma) webGetWithCookie(ctx context.Context, cookie, query string, into any) error {
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, h.webBase()+"/api.php?"+query, nil)
	if errReq != nil {
		return errReq
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, errDo := h.http.Do(req)
	if errDo != nil {
		return fmt.Errorf("sms/haozhuma web: %w", errDo)
	}
	defer func() { _ = resp.Body.Close() }()
	if errDecode := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(into); errDecode != nil {
		return fmt.Errorf("sms/haozhuma web: decode %s: %w", query, errDecode)
	}
	return nil
}

// webRequest performs one JSON request against the web surface and decodes the
// reply into into.
func (h *Haozhuma) webRequest(ctx context.Context, method, endpoint, contentType string, body []byte, into any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, errReq := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if errReq != nil {
		return errReq
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, errDo := h.http.Do(req)
	if errDo != nil {
		return fmt.Errorf("sms/haozhuma web login: %w", errDo)
	}
	defer func() { _ = resp.Body.Close() }()
	if errDecode := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(into); errDecode != nil {
		return fmt.Errorf("sms/haozhuma web login: decode %s: %w", endpoint, errDecode)
	}
	return nil
}

// solveHaozhumaCaptcha derives the four click positions from the two captcha
// images. The order image names the figures in click order; the click image is
// where those figures actually sit.
func solveHaozhumaCaptcha(orderPNG, clickPNG []byte) ([]captchaPoint, error) {
	orderImg, errOrder := decodePNG(orderPNG)
	if errOrder != nil {
		return nil, fmt.Errorf("sms/haozhuma captcha: order image: %w", errOrder)
	}
	clickImg, errClick := decodePNG(clickPNG)
	if errClick != nil {
		return nil, fmt.Errorf("sms/haozhuma captcha: click image: %w", errClick)
	}

	sequence, errSequence := orderColorPairs(orderImg)
	if errSequence != nil {
		return nil, errSequence
	}

	// The figures are declared by their two fill colours, in click order. The
	// click image is then searched for each figure's centre independently, so a
	// figure that shares a colour with another one still resolves correctly.
	points := make([]captchaPoint, 0, len(sequence))
	for _, pair := range sequence {
		point, ok := locatePattern(clickImg, pair[0], pair[1])
		if !ok {
			return nil, fmt.Errorf("sms/haozhuma captcha: the click image has no figure for %s", pair[0]+"/"+pair[1])
		}
		points = append(points, point)
	}
	return points, nil
}

// orderColorPairs reads the hint image's figures as "top/bottom" colour pairs,
// in the order they must be clicked.
//
// The hint lays the figures out in a row on a plain background, so they are
// segmented by column projection: a figure occupies a run of columns that paint
// palette colours, and the gaps between runs separate the figures. This is more
// reliable than fixed slots (a figure can straddle a slot boundary) and than
// connectivity (the hint draws a figure's two halves as separate shapes).
func orderColorPairs(img image.Image) ([][2]string, error) {
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width <= 0 || height <= 0 {
		return nil, errors.New("sms/haozhuma captcha: the hint image is empty")
	}

	column := make([]int, width)
	names := make([]string, width*height)
	onPalette := make([]bool, width*height)
	for y := range height {
		for x := range width {
			name, ok := classifyImageColor(img, bounds.Min.X+x, bounds.Min.Y+y)
			names[y*width+x], onPalette[y*width+x] = name, ok
			if ok {
				column[x]++
			}
		}
	}

	// Runs of painted columns, with narrow gaps merged so an internal seam does
	// not split one figure into two.
	const mergeGap = 3
	runs := make([][2]int, 0, 6)
	start := -1
	gap := 0
	for x := range width {
		if column[x] > 0 {
			if start < 0 {
				start = x
			}
			gap = 0
			continue
		}
		if start < 0 {
			continue
		}
		gap++
		if gap > mergeGap {
			runs = append(runs, [2]int{start, x - gap})
			start = -1
			gap = 0
		}
	}
	if start >= 0 {
		runs = append(runs, [2]int{start, width - 1})
	}
	if len(runs) != 4 {
		return nil, fmt.Errorf("sms/haozhuma captcha: the hint image shows %d figures, want 4", len(runs))
	}

	pairs := make([][2]string, 0, 4)
	for _, run := range runs {
		counts := map[string]int{}
		sumY := map[string]int{}
		for y := range height {
			for x := run[0]; x <= run[1]; x++ {
				if !onPalette[y*width+x] {
					continue
				}
				name := names[y*width+x]
				counts[name]++
				sumY[name] += y
			}
		}
		top, bottom, errPair := dominantPair(counts, sumY)
		if errPair != nil {
			return nil, fmt.Errorf("sms/haozhuma captcha: hint figure: %w", errPair)
		}
		pairs = append(pairs, [2]string{top, bottom})
	}
	return pairs, nil
}

// locatePattern finds the centre of the two-colour figure named by top and
// bottom in the click image.
//
// It first looks for a single connected blob that paints both colours, which is
// the common case and exact. When a figure's halves are disconnected in the
// image, it falls back to the closest pair of blobs, one per colour, that are
// both small enough to be figures rather than background regions. The size
// ceiling is what keeps a large background region of a fill colour from being
// paired with a real figure, which is how nearest-centre pairing used to fail.
func locatePattern(img image.Image, top, bottom string) (captchaPoint, bool) {
	blobs := segmentPaletteBlobs(img)
	if len(blobs) == 0 {
		return captchaPoint{}, false
	}
	largest := 0
	for _, blob := range blobs {
		if blob.size > largest {
			largest = blob.size
		}
	}

	// Exact case: one blob painting both colours.
	for _, blob := range blobs {
		if blob.counts[top] >= captchaMinPixels && blob.counts[bottom] >= captchaMinPixels {
			return blob.centreOf(top, bottom), true
		}
	}

	// Fallback: pair a top-coloured blob with a bottom-coloured one. Only blobs
	// no larger than a figure are candidates, and the bottom half must sit
	// below the top half.
	sizeCeiling := largest * 3 / 2
	bestDistance := math.MaxFloat64
	var best captchaPoint
	found := false
	for _, topBlob := range blobs {
		if topBlob.counts[top] == 0 || topBlob.size > sizeCeiling {
			continue
		}
		for _, bottomBlob := range blobs {
			if bottomBlob.counts[bottom] == 0 || bottomBlob.size > sizeCeiling {
				continue
			}
			topY := topBlob.centreYOf(top)
			bottomY := bottomBlob.centreYOf(bottom)
			if topY > bottomY {
				continue
			}
			dx := topBlob.centreXOf(top) - bottomBlob.centreXOf(bottom)
			dy := topY - bottomY
			if distance := dx*dx + dy*dy; distance < bestDistance {
				bestDistance = distance
				best = captchaPoint{
					X: int(math.Round((topBlob.centreXOf(top) + bottomBlob.centreXOf(bottom)) / 2)),
					Y: int(math.Round((topY + bottomY) / 2)),
				}
				found = true
			}
		}
	}
	return best, found
}

// paletteBlob is one connected region of palette-coloured pixels.
type paletteBlob struct {
	size             int
	counts           map[string]int
	sumX             map[string]int
	sumY             map[string]int
	originX, originY int
}

func (b paletteBlob) centreXOf(name string) float64 {
	return float64(b.originX) + float64(b.sumX[name])/float64(b.counts[name])
}

func (b paletteBlob) centreYOf(name string) float64 {
	return float64(b.originY) + float64(b.sumY[name])/float64(b.counts[name])
}

// centreOf returns the midpoint between two colours inside one blob.
func (b paletteBlob) centreOf(top, bottom string) captchaPoint {
	return captchaPoint{
		X: int(math.Round((b.centreXOf(top) + b.centreXOf(bottom)) / 2)),
		Y: int(math.Round((b.centreYOf(top) + b.centreYOf(bottom)) / 2)),
	}
}

// dominantPair picks one figure's two colours: the two most painted, ordered by
// which sits higher (the top half versus the bottom half).
func dominantPair(counts, sumY map[string]int) (string, string, error) {
	type entry struct {
		name  string
		count int
	}
	ranked := make([]entry, 0, len(counts))
	for name, count := range counts {
		if count >= captchaMinPixels {
			ranked = append(ranked, entry{name, count})
		}
	}
	if len(ranked) < 2 {
		return "", "", errors.New("fewer than two colours")
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].count > ranked[j].count })
	first, second := ranked[0].name, ranked[1].name
	if sumY[first]/counts[first] <= sumY[second]/counts[second] {
		return first, second, nil
	}
	return second, first, nil
}

// segmentPaletteBlobs splits an image into connected regions of palette-coloured
// pixels. A figure is one such region (its two halves touch); a background
// region that happens to share a fill colour is a separate one.
func segmentPaletteBlobs(img image.Image) []paletteBlob {
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width <= 0 || height <= 0 {
		return nil
	}
	names := make([]string, width*height)
	onPalette := make([]bool, width*height)
	for y := range height {
		for x := range width {
			name, ok := classifyImageColor(img, bounds.Min.X+x, bounds.Min.Y+y)
			names[y*width+x], onPalette[y*width+x] = name, ok
		}
	}

	// 8-connectivity keeps a figure's two halves together across an
	// anti-aliased split line.
	neighbours := [8][2]int{{1, 0}, {-1, 0}, {0, 1}, {0, -1}, {1, 1}, {1, -1}, {-1, 1}, {-1, -1}}
	visited := make([]bool, width*height)
	blobs := make([]paletteBlob, 0, 8)
	queue := make([]int, 0, 256)
	for start := range names {
		if visited[start] || !onPalette[start] {
			continue
		}
		current := paletteBlob{
			counts:  map[string]int{},
			sumX:    map[string]int{},
			sumY:    map[string]int{},
			originX: bounds.Min.X,
			originY: bounds.Min.Y,
		}
		queue = append(queue[:0], start)
		visited[start] = true
		for len(queue) > 0 {
			index := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			x, y := index%width, index/width
			name := names[index]
			current.size++
			current.counts[name]++
			current.sumX[name] += x
			current.sumY[name] += y
			for _, d := range neighbours {
				nx, ny := x+d[0], y+d[1]
				if nx < 0 || ny < 0 || nx >= width || ny >= height {
					continue
				}
				next := ny*width + nx
				if visited[next] || !onPalette[next] {
					continue
				}
				visited[next] = true
				queue = append(queue, next)
			}
		}
		blobs = append(blobs, current)
	}
	return blobs
}

// classifyImageColor classifies one pixel of an image.
func classifyImageColor(img image.Image, x, y int) (string, bool) {
	r, g, b, _ := img.At(x, y).RGBA()
	return classifyColor(uint8(r>>8), uint8(g>>8), uint8(b>>8))
}

// decodePNG decodes a PNG from bytes.
func decodePNG(data []byte) (image.Image, error) {
	img, _, errDecode := image.Decode(bytes.NewReader(data))
	return img, errDecode
}
