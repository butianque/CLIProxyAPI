package phone

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newWebServer serves one canned control-plane reply behind the bearer token the
// provider stores, and asserts the request the provider made.
func newWebServer(t *testing.T, wantMethod, wantPath, data string) (*httptest.Server, *Haozhuma) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != wantMethod {
			t.Errorf("method = %q, want %q", r.Method, wantMethod)
		}
		if got := r.URL.RequestURI(); got != wantPath {
			t.Errorf("path = %q, want %q", got, wantPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer session-token" {
			t.Errorf("authorization = %q", got)
		}
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":` + data + `}`))
	}))
	t.Cleanup(server.Close)
	provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "session-token", WebAPI: server.URL}, server.Client())
	if errProvider != nil {
		t.Fatalf("NewHaozhuma: %v", errProvider)
	}
	return server, provider
}

// The joined list carries the price, the stock and the on/off state; the ids are
// the channel codes, and the operators and prefixes arrive as lists.
func TestChannelsParsesJoinedList(t *testing.T) {
	data := `{"list":[` +
		`{"code":"21614-cheap","projectId":"21614","projectName":"\u8baf\u98de","price":"0.13","available":4,"operators":["\u865a\u62df\u8fd0\u8425\u5546"],"prefixes":["165"],"contact":"a","status":"joined"},` +
		`{"code":"21614-over","projectId":"21614","projectName":"\u8baf\u98de","price":"3.30","available":29,"operators":["\u79fb\u52a8","\u8054\u901a"],"prefixes":["199","198"],"contact":"b","status":"paused"}],` +
		`"total":2,"page":1,"size":100}`
	_, provider := newWebServer(t, http.MethodGet, "/bindings?page=1&size=100", data)

	quotes, errChannels := provider.Channels(context.Background())
	if errChannels != nil {
		t.Fatalf("Channels: %v", errChannels)
	}
	if len(quotes) != 2 {
		t.Fatalf("got %d quotes, want 2", len(quotes))
	}
	if quotes[0].UID != "21614-cheap" || quotes[0].Price != 0.13 || quotes[0].Stock != 4 {
		t.Fatalf("quotes[0] = %+v", quotes[0])
	}
	if quotes[0].Carriers != "\u865a\u62df\u8fd0\u8425\u5546" || quotes[0].Paragraphs != "165" {
		t.Fatalf("quotes[0] carriers/prefixes = %q/%q", quotes[0].Carriers, quotes[0].Paragraphs)
	}
	if quotes[0].Paused {
		t.Fatal("quotes[0] should be enabled")
	}
	if quotes[1].Carriers != "\u79fb\u52a8|\u8054\u901a" || !quotes[1].Paused {
		t.Fatalf("quotes[1] = %+v", quotes[1])
	}
}

// The project search answers with both handles on one row; the name is served
// bare, so the keyword comes straight back out of it.
func TestSearchProjectsParsesRows(t *testing.T) {
	data := `{"list":[` +
		`{"id":"21614","sid":"8e41d296bf0c4969","name":"\u8baf\u98de"},` +
		`{"id":"117014","sid":"ae1d7e6b57fe79dc","name":"\u8baf\u98de\u661f\u5149"}],"total":2,"page":1,"size":50}`
	_, provider := newWebServer(t, http.MethodGet, "/projects/search?keyword=%E8%AE%AF%E9%A3%9E&size=50", data)

	refs, errSearch := provider.SearchProjects(context.Background(), "\u8baf\u98de")
	if errSearch != nil {
		t.Fatalf("SearchProjects: %v", errSearch)
	}
	if len(refs) != 2 {
		t.Fatalf("got %d refs, want 2", len(refs))
	}
	if refs[0].ID != "21614" || refs[0].Hash != "8e41d296bf0c4969" {
		t.Fatalf("refs[0] = %+v, want id 21614 and the hash", refs[0])
	}
	if ProjectKeyword(refs[0].Name) != "\u8baf\u98de" {
		t.Fatalf("keyword = %q, want \u8baf\u98de", ProjectKeyword(refs[0].Name))
	}
	if refs[1].ID != "117014" {
		t.Fatalf("refs[1].ID = %q, want 117014", refs[1].ID)
	}
}

// The lookup is by name, and only the entry whose id matches is accepted.
func TestFindProjectMatchesByID(t *testing.T) {
	data := `{"list":[` +
		`{"id":"21614","sid":"8e41d296bf0c4969","name":"\u8baf\u98de"},` +
		`{"id":"117014","sid":"ae1d7e6b57fe79dc","name":"\u8baf\u98de\u661f\u5149"}],"total":2,"page":1,"size":50}`
	_, provider := newWebServer(t, http.MethodGet, "/projects/search?keyword=%E8%AE%AF%E9%A3%9E&size=50", data)

	ref, errFind := provider.FindProject(context.Background(), "117014", "\u8baf\u98de")
	if errFind != nil {
		t.Fatalf("FindProject: %v", errFind)
	}
	if ref.Hash != "ae1d7e6b57fe79dc" {
		t.Fatalf("hash = %q, want the 117014 entry", ref.Hash)
	}
}

// A lookup with no name keyword cannot work, because the platform searches by
// name only; it must be reported instead of silently searching for the id.
func TestFindProjectNeedsKeyword(t *testing.T) {
	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "session-token"}, nil)
	if _, errFind := provider.FindProject(context.Background(), "21614", "  "); errFind == nil {
		t.Fatal("FindProject with no keyword should fail")
	}
}

// The full project list reports every channel, joined or not, parsed the same
// way as the joined list.
func TestAllChannelsParsesList(t *testing.T) {
	data := `[` +
		`{"code":"21614-cheap","projectId":"21614","projectName":"\u8baf\u98de","price":"0.13","available":4,"operators":["\u865a\u62df\u8fd0\u8425\u5546"],"prefixes":["165"],"contact":"a"},` +
		`{"code":"21614-over","projectId":"21614","projectName":"\u8baf\u98de","price":"3.30","available":29,"operators":["\u79fb\u52a8"],"prefixes":["199"],"contact":"b"}]`
	_, provider := newWebServer(t, http.MethodGet, "/projects/8e41d296bf0c4969/public-codes", data)

	quotes, errAll := provider.AllChannels(context.Background(), "8e41d296bf0c4969")
	if errAll != nil {
		t.Fatalf("AllChannels: %v", errAll)
	}
	if len(quotes) != 2 {
		t.Fatalf("got %d quotes, want 2", len(quotes))
	}
	if quotes[0].UID != "21614-cheap" || quotes[0].Price != 0.13 || quotes[0].Stock != 4 {
		t.Fatalf("quotes[0] = %+v", quotes[0])
	}
	if quotes[1].Price != 3.3 || quotes[1].Stock != 29 {
		t.Fatalf("quotes[1] = %+v", quotes[1])
	}
}

// The catalogue is addressed by the project handle, not by the numeric id, and
// the service answers a numeric id with an empty list rather than an error. The
// wrong shape is refused here instead of looking like "this project has no
// channels".
func TestAllChannelsRejectsNumericID(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":[]}`))
	}))
	defer server.Close()
	provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "session-token", WebAPI: server.URL}, server.Client())
	if errProvider != nil {
		t.Fatalf("NewHaozhuma: %v", errProvider)
	}

	if _, errAll := provider.AllChannels(context.Background(), "21614"); errAll == nil {
		t.Fatal("AllChannels with a numeric id should fail")
	}
	if called {
		t.Fatal("a wrong-shaped handle must not be sent to the platform")
	}
}

// Joining reports the channels the platform accepted, and needs a session.
func TestJoinChannelsReportsAccepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/bindings" {
			t.Errorf("%s %s, want POST /bindings", r.Method, r.URL.Path)
		}
		var body struct {
			Codes []string `json:"codes"`
		}
		if errDecode := json.NewDecoder(r.Body).Decode(&body); errDecode != nil {
			t.Errorf("decode body: %v", errDecode)
		}
		if strings.Join(body.Codes, ",") != "21614-a,21614-b" {
			t.Errorf("codes = %v", body.Codes)
		}
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"results":[` +
			`{"code":"21614-a","ok":true,"message":"\u6dfb\u52a0\u6210\u529f"},` +
			`{"code":"21614-b","ok":false,"message":"\u5df2\u5b58\u5728"}]}}`))
	}))
	defer server.Close()
	provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "session-token", WebAPI: server.URL}, server.Client())
	if errProvider != nil {
		t.Fatalf("NewHaozhuma: %v", errProvider)
	}

	joined, errJoin := provider.JoinChannels(context.Background(), []string{"21614-a", "21614-b"})
	if errJoin != nil {
		t.Fatalf("JoinChannels: %v", errJoin)
	}
	if len(joined) != 1 || joined[0] != "21614-a" {
		t.Fatalf("joined = %v, want only the accepted code", joined)
	}
}

func TestJoinChannelsWithoutSession(t *testing.T) {
	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t"}, nil)
	if _, errJoin := provider.JoinChannels(context.Background(), []string{"21614-a"}); errJoin == nil {
		t.Fatal("JoinChannels without a session should fail")
	}
}

// The two surfaces name the delete action differently; the caller keeps the old
// name and the platform sees its own.
func TestSetChannelOpenMapsDelete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/bindings/batch" {
			t.Errorf("%s %s, want POST /bindings/batch", r.Method, r.URL.Path)
		}
		var body struct {
			Action string   `json:"action"`
			Codes  []string `json:"codes"`
		}
		if errDecode := json.NewDecoder(r.Body).Decode(&body); errDecode != nil {
			t.Errorf("decode body: %v", errDecode)
		}
		if body.Action != "delete" || len(body.Codes) != 1 || body.Codes[0] != "21614-a" {
			t.Errorf("body = %+v", body)
		}
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"affected":1}}`))
	}))
	defer server.Close()
	provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "session-token", WebAPI: server.URL}, server.Client())
	if errProvider != nil {
		t.Fatalf("NewHaozhuma: %v", errProvider)
	}

	affected, errSwitch := provider.SetChannelOpen(context.Background(), "del", []string{"21614-a"})
	if errSwitch != nil {
		t.Fatalf("SetChannelOpen: %v", errSwitch)
	}
	if len(affected) != 1 {
		t.Fatalf("affected = %v", affected)
	}
}

// A rejected token is reported as a credential problem, so the caller keeps its
// cached list instead of treating the account as broken.
func TestExpiredSessionIsCredentialError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"message":"Unauthorized","data":{}}`))
	}))
	defer server.Close()
	provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "stale-token", WebAPI: server.URL}, server.Client())
	if errProvider != nil {
		t.Fatalf("NewHaozhuma: %v", errProvider)
	}

	if _, errChannels := provider.Channels(context.Background()); !errors.Is(errChannels, ErrCredential) {
		t.Fatalf("err = %v, want ErrCredential", errChannels)
	}
}

// A gateway that answers 401 with an HTML body still means the session is gone,
// so it is classified as a credential problem rather than a broken platform.
func TestUnauthorizedHTMLBodyIsCredentialError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<html><body>401 Unauthorized</body></html>"))
	}))
	defer server.Close()
	provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "stale-token", WebAPI: server.URL}, server.Client())
	if errProvider != nil {
		t.Fatalf("NewHaozhuma: %v", errProvider)
	}

	if _, errChannels := provider.Channels(context.Background()); !errors.Is(errChannels, ErrCredential) {
		t.Fatalf("err = %v, want ErrCredential", errChannels)
	}
}

// A value left over from the old cookie-based surface is refused with a pointer
// to the sign-in instead of being sent as a token.
func TestLegacyCookieIsRefused(t *testing.T) {
	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "PHPSESSID=abc123"}, nil)
	errChannels := func() error {
		_, errCall := provider.Channels(context.Background())
		return errCall
	}()
	if !errors.Is(errChannels, ErrCredential) {
		t.Fatalf("err = %v, want ErrCredential", errChannels)
	}
}
