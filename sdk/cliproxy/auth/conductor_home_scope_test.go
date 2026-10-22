package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Home owns its own candidate set, so a scoped key can only be kept inside its
// scope by checking the credential Home hands back. Without that check a key
// restricted to one category could execute on an account from another one.
func TestHomeDispatchRejectsCredentialOutsideScope(t *testing.T) {
	dispatcher := &authKindHomeDispatcher{auths: []Auth{
		{ID: "wb-cred", Provider: "workbuddy-global", Attributes: map[string]string{AttributeAPIKey: "wb", "base_url": "https://wb.example.com"}},
	}}
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: true}})
	manager.PublishHomeDispatch(dispatcher, executionregistry.New(), 1)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "workbuddy-global"})

	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.AllowedPoolsMetadataKey: "loomy",
	}}
	auth, _, _, errPick := manager.pickNextViaHome(context.Background(), "gpt-5.4", opts, nil)
	if errPick == nil {
		t.Fatalf("pickNextViaHome() auth = %v, want the out-of-scope dispatch to fail", auth)
	}
	if auth != nil {
		t.Fatalf("pickNextViaHome() returned %q despite being outside the key's scope", auth.ID)
	}
	var authErr *Error
	if !errors.As(errPick, &authErr) || authErr == nil {
		t.Fatalf("pickNextViaHome() error = %v, want an *Error", errPick)
	}
	if !strings.Contains(authErr.Message, "outside the key's scope") {
		t.Fatalf("message = %q, want it to say the credential is outside the scope", authErr.Message)
	}
	if !strings.Contains(authErr.Message, "loomy") {
		t.Fatalf("message = %q, want it to name the scoped entry", authErr.Message)
	}
}

// An unscoped caller must keep reaching whatever Home dispatches, and an in-scope
// caller must still succeed: the check narrows nothing on its own.
func TestHomeDispatchAcceptsInScopeCredential(t *testing.T) {
	for _, tc := range []struct {
		name string
		meta map[string]any
	}{
		{"unscoped", nil},
		{"matching scope", map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "workbuddy-global"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dispatcher := &authKindHomeDispatcher{auths: []Auth{
				{ID: "wb-cred", Provider: "workbuddy-global", Attributes: map[string]string{AttributeAPIKey: "wb", "base_url": "https://wb.example.com"}},
			}}
			manager := NewManager(nil, nil, nil)
			manager.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: true}})
			manager.PublishHomeDispatch(dispatcher, executionregistry.New(), 1)
			manager.RegisterExecutor(schedulerTestExecutor{provider: "workbuddy-global"})

			opts := cliproxyexecutor.Options{Metadata: tc.meta}
			auth, _, _, errPick := manager.pickNextViaHome(context.Background(), "gpt-5.4", opts, nil)
			if errPick != nil {
				t.Fatalf("pickNextViaHome() error = %v", errPick)
			}
			if auth == nil || auth.ID != "wb-cred" {
				t.Fatalf("pickNextViaHome() auth = %v, want wb-cred", auth)
			}
		})
	}
}
