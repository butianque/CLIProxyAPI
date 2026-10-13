package phone

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	const body = `{"code":200,"msg":"成功获取列表","data":[
	  {"uid":"21614-BJJO2R0EUM","mc":"[21614]讯飞","yhj":"0.3850","zxky":"可用数量:19","yyy":"电信|移动|联通|","hd":"190|185|","lxfs":"未留"},
	  {"uid":"21614-E2QJC36FDG","mc":"[21614]讯飞","yhj":"0.1300","zxky":"可用数量:4","yyy":"虚拟运营商|","hd":"165|162|","lxfs":"fafafa66888"},
	  {"uid":"21614-M54KWVSCUE","mc":"[21614]讯飞","yhj":"0.1300","zxky":"可用数量:0","yyy":"电信|","hd":"199|","lxfs":"未留"},
	  {"uid":"58562-OEIO5JKMZH","mc":"[58562]稀土掘金/Trae","yhj":"0.1800","zxky":"可用数量:108","yyy":"移动|","hd":"186|","lxfs":"UW7788"}
	]}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "3" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		if cookie := r.Header.Get("Cookie"); cookie != "PHPSESSID=abc" {
			t.Errorf("cookie = %q, want the session cookie", cookie)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "PHPSESSID=abc", WebBase: server.URL}, server.Client())
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
