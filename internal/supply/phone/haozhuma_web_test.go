package phone

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newWebServer serves one canned /api.php reply and asserts the expected query.
func newWebServer(t *testing.T, wantQuery, body string) (*httptest.Server, *Haozhuma) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RawQuery; got != wantQuery {
			t.Errorf("query = %q, want %q", got, wantQuery)
		}
		if cookie := r.Header.Get("Cookie"); cookie != "PHPSESSID=abc" {
			t.Errorf("cookie = %q", cookie)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	provider, errProvider := NewHaozhuma(HaozhumaSecret{Token: "t", Cookie: "PHPSESSID=abc", WebBase: server.URL}, server.Client())
	if errProvider != nil {
		t.Fatalf("NewHaozhuma: %v", errProvider)
	}
	return server, provider
}

// The project search answers with a label that embeds both handles; the numeric
// id and the hash must both be extracted from it.
func TestSearchProjectsParsesLabel(t *testing.T) {
	body := `{"code":1,"msg":"Success","data":[` +
		`{"name":"\u301021614\u3011\u8baf\u98de                    [8e41d296bf0c4969]","sid":"8e41d296bf0c4969"},` +
		`{"name":"\u3010117014\u3011\u8baf\u98de\u661f\u5149          [ae1d7e6b57fe79dc]","sid":"ae1d7e6b57fe79dc"}]}`
	_, provider := newWebServer(t, "type=30&gjc=%E8%AE%AF%E9%A3%9E", body)

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
	body := `{"code":1,"msg":"Success","data":[` +
		`{"name":"\u301021614\u3011\u8baf\u98de [8e41d296bf0c4969]","sid":"8e41d296bf0c4969"},` +
		`{"name":"\u3010117014\u3011\u8baf\u98de\u661f\u5149 [ae1d7e6b57fe79dc]","sid":"ae1d7e6b57fe79dc"}]}`
	_, provider := newWebServer(t, "type=30&gjc=%E8%AE%AF%E9%A3%9E", body)

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
	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t"}, nil)
	if _, errFind := provider.FindProject(context.Background(), "21614", "  "); errFind == nil {
		t.Fatal("FindProject with no keyword should fail")
	}
}

// The full project list reports every channel, joined or not, parsed the same
// way as the joined list.
func TestAllChannelsParsesList(t *testing.T) {
	body := `{"code":1,"msg":"Success","data":[` +
		`{"uid":"21614-cheap","mc":"[21614]\u8baf\u98de","yhj":"0.13","zxky":"\u53ef\u7528\u6570\u91cf:4","yyy":"\u865a\u62df\u8fd0\u8425\u5546|","hd":"165|","lxfs":"a"},` +
		`{"uid":"21614-over","mc":"[21614]\u8baf\u98de","yhj":"3.30","zxky":"\u53ef\u7528\u6570\u91cf:29","yyy":"\u79fb\u52a8|","hd":"199|","lxfs":"b"}]}`
	_, provider := newWebServer(t, "type=8&sid=hash21614", body)

	quotes, errAll := provider.AllChannels(context.Background(), "hash21614")
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

// Joining reports the channels the platform accepted, and needs a session.
func TestJoinChannelsReportsAccepted(t *testing.T) {
	body := `{"code":200,"data":[{"uid":"21614-a","status":"\u6dfb\u52a0\u6210\u529f"},{"uid":"21614-b","status":"\u6dfb\u52a0\u6210\u529f"}],"msg":"\u5b8c\u6210"}`
	_, provider := newWebServer(t, "type=43&djm=21614-a%2C21614-b", body)

	joined, errJoin := provider.JoinChannels(context.Background(), []string{"21614-a", "21614-b"})
	if errJoin != nil {
		t.Fatalf("JoinChannels: %v", errJoin)
	}
	if len(joined) != 2 || joined[0] != "21614-a" {
		t.Fatalf("joined = %v", joined)
	}
}

func TestJoinChannelsWithoutCookie(t *testing.T) {
	provider, _ := NewHaozhuma(HaozhumaSecret{Token: "t"}, nil)
	if _, errJoin := provider.JoinChannels(context.Background(), []string{"21614-a"}); errJoin == nil {
		t.Fatal("JoinChannels without a cookie should fail")
	}
}
