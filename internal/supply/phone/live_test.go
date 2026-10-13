package phone

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveFreeCalls exercises the real platform, but only the free endpoints:
// the balance and the joined-channel list. It is skipped unless HZ_TOKEN is set,
// so the ordinary test run never touches the network.
//
// It deliberately never rents a number: getPhone costs money.
func TestLiveFreeCalls(t *testing.T) {
	token := os.Getenv("HZ_TOKEN")
	if token == "" {
		t.Skip("set HZ_TOKEN (and optionally HZ_COOKIE) to run the live check")
	}
	provider, errProvider := NewHaozhuma(HaozhumaSecret{
		Token:  token,
		Cookie: os.Getenv("HZ_COOKIE"),
	}, nil)
	if errProvider != nil {
		t.Fatalf("NewHaozhuma: %v", errProvider)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	balance, errBalance := provider.Balance(ctx)
	if errBalance != nil {
		t.Fatalf("Balance: %v", errBalance)
	}
	t.Logf("balance = %.3f CNY", balance)

	if os.Getenv("HZ_COOKIE") == "" {
		t.Log("no cookie set, skipping the channel list")
		return
	}
	quotes, errChannels := provider.Channels(ctx)
	if errChannels != nil {
		t.Fatalf("Channels: %v", errChannels)
	}
	cheapest, inStock := 0.0, 0
	for _, quote := range quotes {
		if quote.Stock > 0 {
			inStock++
			if cheapest == 0 || quote.Price < cheapest {
				cheapest = quote.Price
			}
		}
	}
	t.Logf("channels = %d, in stock = %d, cheapest = %.3f CNY", len(quotes), inStock, cheapest)
	for i, quote := range quotes {
		if i >= 6 {
			break
		}
		t.Logf("  %s price=%.3f stock=%d carriers=%s", quote.UID, quote.Price, quote.Stock, quote.Carriers)
	}

	// The list must already be ordered cheapest first, as the service relies on.
	for i := 1; i < len(quotes); i++ {
		if quotes[i-1].Price > quotes[i].Price {
			t.Fatalf("channel list is not ordered cheapest first at %d: %.3f then %.3f",
				i, quotes[i-1].Price, quotes[i].Price)
		}
	}

	// The project handle must resolve for a project that is actually joined,
	// from its name rather than its id (the platform searches by name only).
	sid := os.Getenv("HZ_PROJECT")
	if sid == "" {
		sid = "21614"
	}
	keyword := ""
	for _, quote := range quotes {
		if strings.HasPrefix(quote.UID, sid+"-") {
			keyword = ProjectKeyword(quote.Name)
			break
		}
	}
	if keyword == "" {
		t.Skipf("no joined %s channel to source the project name from", sid)
	}
	ref, errFind := provider.FindProject(ctx, sid, keyword)
	if errFind != nil {
		t.Fatalf("FindProject(%s, %q): %v", sid, keyword, errFind)
	}
	t.Logf("project %s -> hash %s (%s)", sid, ref.Hash, ref.Name)

	all, errAll := provider.AllChannels(ctx, ref.Hash)
	if errAll != nil {
		t.Fatalf("AllChannels: %v", errAll)
	}
	affordable := 0
	for _, quote := range all {
		if strings.HasPrefix(quote.UID, sid+"-") && quote.Price > 0 && quote.Price <= 0.5 {
			affordable++
		}
	}
	t.Logf("all channels = %d, affordable (<=0.5 CNY) = %d", len(all), affordable)
}
