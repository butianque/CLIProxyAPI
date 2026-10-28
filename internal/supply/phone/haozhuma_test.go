package phone

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ParseHaozhumaCookie accepts either the bare cookie the browser exposes or a
// JSON object, so the operator can paste whichever form they have.
func TestParseHaozhumaCookieAcceptsBareAndJSON(t *testing.T) {
	bare, errBare := ParseHaozhumaCookie("  PHPSESSID=abc123  ")
	if errBare != nil {
		t.Fatalf("bare: %v", errBare)
	}
	if bare.Cookie != "PHPSESSID=abc123" {
		t.Fatalf("bare cookie = %q", bare.Cookie)
	}

	fromJSON, errJSON := ParseHaozhumaCookie(`{"cookie":"PHPSESSID=xyz","web_base":"https://h5.haozhuma.com"}`)
	if errJSON != nil {
		t.Fatalf("json: %v", errJSON)
	}
	if fromJSON.Cookie != "PHPSESSID=xyz" || fromJSON.WebBase != "https://h5.haozhuma.com" {
		t.Fatalf("json cookie = %+v", fromJSON)
	}

	if _, errEmpty := ParseHaozhumaCookie("   "); errEmpty == nil {
		t.Fatal("an empty cookie secret must be rejected")
	}
}

// The channel list arrives from the web surface with the stock as a label and
// the price as a string, and includes projects other than the one we rent from.
func TestChannelsParsesWebPayload(t *testing.T) {
	const body = `{"code":0,"message":"ok","data":{"list":[
	  {"code":"21614-BJJO2R0EUM","projectId":"21614","projectName":"\u8baf\u98de","price":"0.3850","available":19,"operators":["\u7535\u4fe1","\u79fb\u52a8","\u8054\u901a"],"prefixes":["190","185"],"contact":"\u672a\u7559","status":"joined"},
	  {"code":"21614-E2QJC36FDG","projectId":"21614","projectName":"\u8baf\u98de","price":"0.1300","available":4,"operators":["\u865a\u62df\u8fd0\u8425\u5546"],"prefixes":["165","162"],"contact":"fafafa66888","status":"joined"},
	  {"code":"21614-M54KWVSCUE","projectId":"21614","projectName":"\u8baf\u98de","price":"0.1300","available":0,"operators":["\u7535\u4fe1"],"prefixes":["199"],"contact":"\u672a\u7559","status":"paused"},
	  {"code":"58562-OEIO5JKMZH","projectId":"58562","projectName":"\u7a00\u571f\u6398\u91d1/Trae","price":"0.1800","available":108,"operators":["\u79fb\u52a8"],"prefixes":["186"],"contact":"UW7788","status":"joined"}
	],"total":4,"page":1,"size":100}}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RequestURI(); got != "/bindings?page=1&size=100" {
			t.Errorf("unexpected path: %s", got)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer token-abc" {
			t.Errorf("authorization = %q, want the session token", auth)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "token-abc", WebAPI: server.URL}, server.Client())
	if errProvider != nil {
		t.Fatalf("NewHaozhuma: %v", errProvider)
	}

	quotes, errChannels := provider.Channels(context.Background())
	if errChannels != nil {
		t.Fatalf("Channels: %v", errChannels)
	}
	if len(quotes) != 4 {
		t.Fatalf("got %d quotes, want 4", len(quotes))
	}
	// Cheapest first, then deepest stock.
	if quotes[0].UID != "21614-E2QJC36FDG" || quotes[0].Price != 0.13 || quotes[0].Stock != 4 {
		t.Fatalf("first quote = %+v, want the 0.13 channel", quotes[0])
	}
	if quotes[1].UID != "21614-M54KWVSCUE" || quotes[1].Stock != 0 {
		t.Fatalf("second quote = %+v, want the zero-stock 0.13 channel", quotes[1])
	}
	if !quotes[1].Paused {
		t.Fatal("the paused channel must be reported as paused")
	}
	if quotes[2].UID != "58562-OEIO5JKMZH" {
		t.Fatalf("third quote = %+v, want the 0.18 channel", quotes[2])
	}
}

// A channel list request without a cookie cannot succeed, and must report a
// credential problem so the caller keeps its cache.
func TestChannelsWithoutCookie(t *testing.T) {
	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t"}, nil)
	if _, errChannels := provider.Channels(context.Background()); !errors.Is(errChannels, ErrCredential) {
		t.Fatalf("err = %v, want ErrCredential", errChannels)
	}
}

// getPhone reports all of its fields at the top level, with sid and uid as
// strings or numbers depending on the reply.
func TestRentParsesReply(t *testing.T) {
	const body = `{"code":"0","msg":"成功","sid":"21614","phone":"13800000000","sp":"移动","phone_gsd":"广东 广州","uid":"21614-E2QJC36FDG"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api") != "getPhone" {
			t.Errorf("api = %q, want getPhone", r.URL.Query().Get("api"))
		}
		if r.URL.Query().Get("uid") != "21614-E2QJC36FDG" {
			t.Errorf("uid = %q, want the pinned channel", r.URL.Query().Get("uid"))
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t", Endpoint: server.URL}, server.Client())
	number, errRent := provider.Rent(context.Background(), Project{SID: "21614"}, "21614-E2QJC36FDG")
	if errRent != nil {
		t.Fatalf("Rent: %v", errRent)
	}
	if number.Phone != "13800000000" || number.Carrier != "移动" || number.Region != "广东 广州" {
		t.Fatalf("number = %+v", number)
	}
	if number.SID != "21614" || number.Code != "21614-E2QJC36FDG" {
		t.Fatalf("number = %+v, want sid and channel", number)
	}
}

// A numeric code field is accepted as well as a string one.
func TestRentAcceptsNumericCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"msg":"success","phone":"13800000001","sid":21614}`))
	}))
	defer server.Close()

	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t", Endpoint: server.URL}, server.Client())
	number, errRent := provider.Rent(context.Background(), Project{SID: "21614"}, "")
	if errRent != nil {
		t.Fatalf("Rent: %v", errRent)
	}
	if number.Phone != "13800000001" {
		t.Fatalf("number = %+v", number)
	}
}

// A message that has not arrived yet is the ordinary polling outcome, reported
// as ErrNotReady rather than a failure.
func TestReadNotReady(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":"-1","msg":"暂无短信"}`))
	}))
	defer server.Close()

	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t", Endpoint: server.URL}, server.Client())
	if _, errRead := provider.Read(context.Background(), Project{SID: "21614"}, "13800000000"); !errors.Is(errRead, ErrNotReady) {
		t.Fatalf("err = %v, want ErrNotReady", errRead)
	}
}

// A delivered message yields both the code and the body.
func TestReadDelivers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":"0","msg":"成功","sms":"【讯飞】验证码为：5184","yzm":"5184"}`))
	}))
	defer server.Close()

	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t", Endpoint: server.URL}, server.Client())
	message, errRead := provider.Read(context.Background(), Project{SID: "21614"}, "13800000000")
	if errRead != nil {
		t.Fatalf("Read: %v", errRead)
	}
	if !message.Ready || message.Code != "5184" {
		t.Fatalf("message = %+v", message)
	}
}

// The balance is reported at the top level of getSummary.
func TestBalanceParsesSummary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"msg":null,"code":0,"money":"3.190","num":"100"}`))
	}))
	defer server.Close()

	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t", Endpoint: server.URL}, server.Client())
	balance, errBalance := provider.Balance(context.Background())
	if errBalance != nil {
		t.Fatalf("Balance: %v", errBalance)
	}
	if balance != 3.19 {
		t.Fatalf("balance = %v, want 3.19", balance)
	}
}

// A probe makes exactly one authenticated call and reports a short detail. It
// must never return a credential value, and a failure it could not even attempt
// (an absent credential) is ErrProbeUnready rather than a plain failure.
func TestProbeAPIReportsBalance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api") != "getSummary" {
			t.Errorf("api = %q, want getSummary", r.URL.Query().Get("api"))
		}
		_, _ = w.Write([]byte(`{"msg":null,"code":0,"money":"2.290","num":"100"}`))
	}))
	defer server.Close()

	detail, errProbe := probeAPI(context.Background(), server.Client(), server.URL, `{"token":"fake-token"}`)
	if errProbe != nil {
		t.Fatalf("probeAPI: %v", errProbe)
	}
	if detail != "balance ¥2.29" {
		t.Fatalf("detail = %q, want the balance", detail)
	}
	if strings.Contains(detail, "fake-token") {
		t.Fatalf("detail %q leaked the credential", detail)
	}
}

// The platform answering with a rejection is a plain failure, not "not ready":
// the request was sent, so the caller must report the channel as offline.
func TestProbeAPIPlatformRefusalIsNotUnready(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":-1,"msg":"token error"}`))
	}))
	defer server.Close()

	if _, errProbe := probeAPI(context.Background(), server.Client(), server.URL, `{"token":"fake-token"}`); errProbe == nil {
		t.Fatal("probeAPI: want an error for a refused token")
	} else if errors.Is(errProbe, ErrProbeUnready) {
		t.Fatalf("err = %v, want a plain failure (offline), not ErrProbeUnready", errProbe)
	}
}

// A credential that cannot be used means nothing was sent anywhere: that is
// "not ready", and the caller must not blame the platform for it.
func TestProbeAPICredentialProblemsAreUnready(t *testing.T) {
	cases := []struct {
		name       string
		endpoint   string
		credential string
	}{
		{name: "empty credential", endpoint: "https://api.haozhuma.cn", credential: "   "},
		{name: "not a json object", endpoint: "https://api.haozhuma.cn", credential: "not json"},
		{name: "no token and no account", endpoint: "https://api.haozhuma.cn", credential: `{"cookie":"PHPSESSID=x"}`},
		{name: "unusable endpoint", endpoint: "://bad", credential: `{"token":"t"}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, errProbe := probeAPI(context.Background(), nil, testCase.endpoint, testCase.credential)
			if !errors.Is(errProbe, ErrProbeUnready) {
				t.Fatalf("err = %v, want ErrProbeUnready", errProbe)
			}
		})
	}
}

// The web probe authenticates with the session token alone: listing channels
// never touches the SMS API, so a token-only channel is still probeable.
func TestProbeWebReportsChannels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer token-abc" {
			t.Errorf("authorization = %q, want the session token", auth)
		}
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","data":{"list":[
		  {"code":"1-A","projectId":"1","projectName":"A","price":"0.10","available":1,"status":"joined"},
		  {"code":"2-B","projectId":"2","projectName":"B","price":"0.20","available":2,"status":"joined"}
		],"total":2,"page":1,"size":100}}`))
	}))
	defer server.Close()

	detail, errProbe := probeWeb(context.Background(), server.Client(), server.URL, `{"cookie":"token-abc"}`)
	if errProbe != nil {
		t.Fatalf("probeWeb: %v", errProbe)
	}
	if detail != "2 channels" {
		t.Fatalf("detail = %q, want the channel count", detail)
	}
}

// A credential that carries no session cannot be probed, and the endpoint the
// credential names is what the probe calls.
func TestProbeWebNeedsACookie(t *testing.T) {
	if _, errProbe := probeWeb(context.Background(), nil, "", `{"token":"t"}`); !errors.Is(errProbe, ErrProbeUnready) {
		t.Fatalf("err = %v, want ErrProbeUnready", errProbe)
	}
}

// A transport failure reports the platform, not the credential. The API
// authenticates with query parameters, so the raw error — which carries the
// address it failed on — would hand the token to whoever reads the panel.
func TestProbeAPITransportErrorHidesTheCredential(t *testing.T) {
	const token = "sk-live-do-not-echo"
	// Port 1 is reserved and never listening: connecting fails without a server.
	_, errProbe := probeAPI(context.Background(), &http.Client{Timeout: time.Second}, "http://127.0.0.1:1", `{"token":"`+token+`"}`)
	if errProbe == nil {
		t.Fatal("probeAPI: want a transport failure")
	}
	if strings.Contains(errProbe.Error(), token) {
		t.Fatalf("error %q leaked the credential", errProbe.Error())
	}
	if errors.Is(errProbe, ErrProbeUnready) {
		t.Fatalf("err = %v, want a plain failure (offline), not ErrProbeUnready", errProbe)
	}
}

// The platform's own text can quote the request back — a proxy error page is the
// usual way, and the client quotes the reply body when it is not the JSON
// envelope it expects. The credential must not travel out on that path either.
func TestProbeAPIPlatformEchoHidesTheCredential(t *testing.T) {
	const token = "sk-live-do-not-echo"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A gateway reporting the address it refused: the token is in the query.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("403 Forbidden: " + r.URL.String()))
	}))
	defer server.Close()

	_, errProbe := probeAPI(context.Background(), server.Client(), server.URL, `{"token":"`+token+`"}`)
	if errProbe == nil {
		t.Fatal("probeAPI: want a failure for a refused request")
	}
	if strings.Contains(errProbe.Error(), token) {
		t.Fatalf("error %q leaked the credential", errProbe.Error())
	}
	// The status proves the reply body was quoted into the error and then swept:
	// without that, the test would pass just because nothing reached the server.
	if !strings.Contains(errProbe.Error(), "403") {
		t.Fatalf("error %q does not quote the refused reply", errProbe.Error())
	}
	if errors.Is(errProbe, ErrProbeUnready) {
		t.Fatalf("err = %v, want a plain failure (offline), not ErrProbeUnready", errProbe)
	}
}

// A base address written without a scheme is completed to https, so an operator
// who pastes "api.haozhuma.com" reaches the API instead of failing later on a
// scheme-less URL. An explicit scheme is respected, and a blank address still
// falls back to the platform default.
func TestNewHaozhumaNormalizesEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "no scheme", endpoint: "api.haozhuma.com", want: "https://api.haozhuma.com"},
		{name: "no scheme with trailing slash", endpoint: "api.haozhuma.com/", want: "https://api.haozhuma.com"},
		{name: "trailing slash is trimmed", endpoint: "https://api.haozhuma.com/", want: "https://api.haozhuma.com"},
		{name: "blank falls back to the default", endpoint: "   ", want: haozhumaDefaultEndpoint},
		{name: "explicit http is kept", endpoint: "http://api.haozhuma.com", want: "http://api.haozhuma.com"},
		{name: "port is kept", endpoint: "api.haozhuma.com:8443", want: "https://api.haozhuma.com:8443"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Endpoint: testCase.endpoint}, nil)
			if errProvider != nil {
				t.Fatalf("NewHaozhuma(%q): %v", testCase.endpoint, errProvider)
			}
			if got := provider.Endpoint(); got != testCase.want {
				t.Fatalf("Endpoint() for %q = %q, want %q", testCase.endpoint, got, testCase.want)
			}
		})
	}
}

// An address that is not an http(s) URL is rejected while the credential is
// read, rather than surfacing later as a failed request.
func TestNewHaozhumaRejectsInvalidEndpoint(t *testing.T) {
	for _, endpoint := range []string{"://bad", "ht tp://x", "ftp://x", "https://"} {
		t.Run(endpoint, func(t *testing.T) {
			provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Endpoint: endpoint}, nil)
			if provider != nil {
				t.Fatalf("NewHaozhuma(%q) returned a provider", endpoint)
			}
			if !errors.Is(errProvider, ErrEndpoint) {
				t.Fatalf("err = %v, want ErrEndpoint", errProvider)
			}
		})
	}
}

// The control-plane base is completed the same way as the API endpoint, so a
// scheme-less address still works. A value naming one of the vendor's own hosts
// is read as "follow the vendor", because it was written for the surface that
// moved.
func TestWebAPIBaseResolvesControlPlane(t *testing.T) {
	cases := []struct {
		name    string
		webBase string
		webAPI  string
		want    string
	}{
		{name: "no scheme", webBase: "phone.example.test", want: "https://phone.example.test"},
		{name: "no scheme with trailing slash", webBase: "phone.example.test/", want: "https://phone.example.test"},
		{name: "trailing slash is trimmed", webBase: "https://phone.example.test/", want: "https://phone.example.test"},
		{name: "blank falls back to the default", want: haozhumaDefaultWebAPI},
		{name: "explicit http is kept", webBase: "http://phone.example.test", want: "http://phone.example.test"},
		{name: "unusable falls back to the default", webBase: "://bad", want: haozhumaDefaultWebAPI},
		{name: "the old site follows the vendor", webBase: "h5.haozhuma.com", want: haozhumaDefaultWebAPI},
		{name: "the old api host follows the vendor", webBase: "https://api.haozhuma.cn", want: haozhumaDefaultWebAPI},
		{name: "web_api wins over web_base", webBase: "h5.haozhuma.cn", webAPI: "https://api.example.test/v1", want: "https://api.example.test/v1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", WebBase: testCase.webBase, WebAPI: testCase.webAPI}, nil)
			if errProvider != nil {
				t.Fatalf("NewHaozhuma(web_base=%q, web_api=%q): %v", testCase.webBase, testCase.webAPI, errProvider)
			}
			if got := provider.webAPIBase(); got != testCase.want {
				t.Fatalf("webAPIBase() for %q/%q = %q, want %q", testCase.webBase, testCase.webAPI, got, testCase.want)
			}
		})
	}
}

// MaskIdentifier keeps a recognisable but non-revealing label for the panel.
//
// The fixtures are made-up values, not real credentials: the point is the shape
// of the mask, and the middle of every mask must never carry source characters.
func TestMaskIdentifier(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "", want: ""},
		{name: "blank", value: "   ", want: ""},
		{name: "four collapses", value: "abcd", want: "••••"},
		{name: "five keeps head", value: "abcde", want: "a••••"},
		{name: "six keeps head", value: "abcdef", want: "a••••"},
		{name: "seven keeps both ends", value: "abcdefg", want: "ab••••fg"},
		{name: "long key", value: "e3c1fb5e000000000000000000000000000000000000447f8", want: "e3••••f8"},
		{name: "account", value: "linhua888", want: "li••••88"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := MaskIdentifier(testCase.value)
			if got != testCase.want {
				t.Fatalf("MaskIdentifier(%q) = %q, want %q", testCase.value, got, testCase.want)
			}
			// A mask must never echo back a character from its own middle.
			if len(testCase.value) > 6 && len(got) > 4 {
				middle := testCase.value[2 : len(testCase.value)-2]
				if strings.Contains(got, middle) {
					t.Fatalf("MaskIdentifier(%q) = %q leaks the middle %q", testCase.value, got, middle)
				}
			}
		})
	}
}
