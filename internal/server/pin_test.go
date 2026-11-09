package server

import "testing"

// Names that issued tokens, open sessions and receivers of webhooks depend on keep the names the project had before
// it was renamed (ADR 0017); a search and replace of the old name must not change them.
func TestWireNamesAreFrozen(t *testing.T) {
	if scopePrefix[ScopeIngest] != "hlt_ing_" || scopePrefix[ScopeAPI] != "hlt_api_" || scopePrefix[ScopeOperator] != "hlt_opr_" {
		t.Errorf("token prefixes = %v", scopePrefix)
	}
	if SessionCookie != "hl_session" {
		t.Errorf("session cookie = %q", SessionCookie)
	}
	if HeaderWebhookSignature != "X-Hostlint-Signature-256" {
		t.Errorf("webhook signature header = %q", HeaderWebhookSignature)
	}
}
