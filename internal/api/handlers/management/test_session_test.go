package management

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
)

// newTestSession registers a session the way the panel would.
//
// Secret handlers authorize per session, so a test that drives them without one
// exercises a path the panel never takes and would silently stop covering the
// behaviour it names.
func newTestSession(t *testing.T, h *Handler) *managementSession {
	t.Helper()
	session, _, errCreate := h.ensureSessions().create("127.0.0.1")
	if errCreate != nil {
		t.Fatalf("create test session: %v", errCreate)
	}
	return session
}

// attachTestSession gives a test router that session, and keeps its secret-store
// grant in step with the store.
//
// The grant is applied per request because a test may open the store after the
// router is built; a real panel unlocks once and the grant then simply persists.
func attachTestSession(t *testing.T, h *Handler, r *gin.Engine) *managementSession {
	t.Helper()
	session := newTestSession(t, h)
	r.Use(func(c *gin.Context) {
		if store := secretstore.Default(); store != nil && store.Unlocked() && !store.SessionUnlocked(session.id) {
			if _, errGrant := store.GrantSession(session.id, time.Minute); errGrant != nil {
				t.Errorf("grant test session: %v", errGrant)
			}
		}
		c.Set(sessionContextKey, session)
		c.Next()
	})
	return session
}
