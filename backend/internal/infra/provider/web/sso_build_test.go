package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
)

type scriptedSSOClient struct {
	responses []*http.Response
	requests  []*http.Request
	errOn     map[int]error // 1-based call index -> error
	calls     atomic.Int64
}

func (c *scriptedSSOClient) Do(request *http.Request) (*http.Response, error) {
	c.requests = append(c.requests, request)
	n := int(c.calls.Add(1))
	if c.errOn != nil {
		if err, ok := c.errOn[n]; ok {
			return nil, err
		}
	}
	if len(c.responses) == 0 {
		return nil, io.EOF
	}
	response := c.responses[0]
	c.responses = c.responses[1:]
	return response, nil
}

func jsonBody(v any) io.ReadCloser {
	raw, _ := json.Marshal(v)
	return io.NopCloser(strings.NewReader(string(raw)))
}

func textResp(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

func found(location string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": []string{location}},
		Body:       io.NopCloser(strings.NewReader("")),
	}
}

func deviceCodeResp(code, user, verify string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body: jsonBody(map[string]any{
			"device_code": code, "user_code": user,
			"verification_uri_complete": verify,
			"interval":                  1, "expires_in": 600,
		}),
	}
}

func tokenOKResp() *http.Response {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1","email":"a@example.com"}`))
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body: jsonBody(map[string]any{
			"access_token": "access-ok", "refresh_token": "refresh-ok",
			"id_token": "hdr." + payload + ".sig", "expires_in": 3600,
		}),
	}
}

func pendingTokenResp() *http.Response {
	return textResp(http.StatusOK, `{"error":"authorization_pending"}`)
}

func instantSleep(context.Context, time.Duration) error { return nil }

func TestSSOBuildFlowFollowsOnlyTrustedXAIHTTPSRedirects(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://auth.x.ai/next"}, "Set-Cookie": []string{"session=abc; Path=/; Secure"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "test-agent", cookies: map[string]string{"sso": "secret"}}
	status, finalURL, body, err := flow.do(context.Background(), http.MethodGet, ssoAccountsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || finalURL != "https://auth.x.ai/next" || string(body) != "ok" {
		t.Fatalf("response = %d %s %q", status, finalURL, body)
	}
	if len(client.requests) != 2 || client.requests[1].Header.Get("User-Agent") != "test-agent" {
		t.Fatalf("requests = %#v", client.requests)
	}
	cookie := client.requests[1].Header.Get("Cookie")
	if !strings.Contains(cookie, "sso=secret") || !strings.Contains(cookie, "session=abc") {
		t.Fatalf("redirect cookies = %q", cookie)
	}

	unsafe := &scriptedSSOClient{responses: []*http.Response{{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://example.com/steal"}}, Body: io.NopCloser(strings.NewReader(""))}}}
	flow = &ssoBuildFlow{client: unsafe, userAgent: "test-agent", cookies: map[string]string{"sso": "secret"}}
	if _, _, _, err := flow.do(context.Background(), http.MethodGet, ssoAccountsURL, nil); err == nil {
		t.Fatal("unsafe redirect was accepted")
	}
}

func TestSSOBuildConversionSanitizesTokenAndURLs(t *testing.T) {
	if token := normalizeSSOToken("sso=token-value; x-userid=drop"); token != "token-value" {
		t.Fatalf("token = %q", token)
	}
	for _, value := range []string{"https://accounts.x.ai/", "https://auth.x.ai/oauth2/device/code"} {
		if !safeXAIURL(value) {
			t.Fatalf("trusted URL rejected: %s", value)
		}
	}
	for _, value := range []string{"http://auth.x.ai/", "https://x.ai.example.com/", "https://user@auth.x.ai/"} {
		if safeXAIURL(value) {
			t.Fatalf("unsafe URL accepted: %s", value)
		}
	}
}

func TestIsSSOConversionRateLimited(t *testing.T) {
	if !isSSOConversionRateLimited(http.StatusTooManyRequests, "", "") {
		t.Fatal("429 status should be rate limited")
	}
	if !isSSOConversionRateLimited(http.StatusOK, "", `{"error":"slow_down"}`) {
		t.Fatal("slow_down body should be rate limited")
	}
	if isSSOConversionRateLimited(http.StatusOK, "https://accounts.x.ai/consent", "ok") {
		t.Fatal("normal response should not be rate limited")
	}
}

func TestSSOBuildConvertRetriesAfterVerifyRateLimit(t *testing.T) {
	verifyURL := "https://accounts.x.ai/oauth2/device?user_code=ABCD"
	client := &scriptedSSOClient{responses: []*http.Response{
		textResp(http.StatusOK, "accounts-ok"),
		deviceCodeResp("dc1", "UC1", verifyURL),
		textResp(http.StatusOK, "verify-page-1"),
		textResp(http.StatusTooManyRequests, `{"error":"slow_down"}`),
		deviceCodeResp("dc2", "UC2", verifyURL),
		textResp(http.StatusOK, "verify-page-2"),
		found("https://accounts.x.ai/oauth2/consent"),
		textResp(http.StatusOK, "consent-page"),
		found("https://accounts.x.ai/oauth2/device/done"),
		textResp(http.StatusOK, "done-page"),
		pendingTokenResp(),
		tokenOKResp(),
	}}
	flow := &ssoBuildFlow{
		client: client, userAgent: "test-agent",
		cookies: map[string]string{"sso": "secret", "sso-rw": "secret"},
		sleep:   instantSleep,
	}
	seed, err := flow.convert(context.Background(), accountdomain.Credential{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != "access-ok" || seed.RefreshToken != "refresh-ok" {
		t.Fatalf("seed = %#v", seed)
	}
	if seed.Email != "a@example.com" || seed.UserID != "user-1" {
		t.Fatalf("claims = email=%q user=%q", seed.Email, seed.UserID)
	}
	devicePosts := 0
	for _, req := range client.requests {
		if req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/device/code") {
			devicePosts++
		}
	}
	if devicePosts < 2 {
		t.Fatalf("device code posts = %d, want >= 2", devicePosts)
	}
}

func TestSSOBuildConvertAllowsApproveWithoutConsentURL(t *testing.T) {
	verifyURL := "https://accounts.x.ai/oauth2/device?user_code=ZZ"
	client := &scriptedSSOClient{responses: []*http.Response{
		textResp(http.StatusOK, "accounts-ok"),
		deviceCodeResp("dc", "UC", verifyURL),
		textResp(http.StatusOK, "verify-page"),
		// verify 200 without consent in URL — old g2a failed, GM continues.
		textResp(http.StatusOK, "ok"),
		found("https://accounts.x.ai/oauth2/device/done"),
		textResp(http.StatusOK, "done-page"),
		pendingTokenResp(),
		tokenOKResp(),
	}}
	flow := &ssoBuildFlow{
		client: client, userAgent: "test-agent",
		cookies: map[string]string{"sso": "secret"},
		sleep:   instantSleep,
	}
	seed, err := flow.convert(context.Background(), accountdomain.Credential{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != "access-ok" {
		t.Fatalf("seed = %#v", seed)
	}
}

func TestSSOBuildConvertAcceptsApproveDoneWithNon2xx(t *testing.T) {
	verifyURL := "https://accounts.x.ai/oauth2/device?user_code=ZZ"
	client := &scriptedSSOClient{responses: []*http.Response{
		textResp(http.StatusOK, "accounts-ok"),
		deviceCodeResp("dc", "UC", verifyURL),
		textResp(http.StatusOK, "verify-page"),
		found("https://accounts.x.ai/oauth2/consent"),
		textResp(http.StatusOK, "consent"),
		found("https://accounts.x.ai/oauth2/device/done"),
		textResp(http.StatusForbidden, "done-with-403"),
		pendingTokenResp(),
		tokenOKResp(),
	}}
	flow := &ssoBuildFlow{
		client: client, userAgent: "test-agent",
		cookies: map[string]string{"sso": "secret"},
		sleep:   instantSleep,
	}
	seed, err := flow.convert(context.Background(), accountdomain.Credential{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != "access-ok" {
		t.Fatalf("seed = %#v", seed)
	}
}

func TestSSOBuildConvertRetriesDeviceCodeRateLimit(t *testing.T) {
	verifyURL := "https://accounts.x.ai/oauth2/device?user_code=ZZ"
	client := &scriptedSSOClient{responses: []*http.Response{
		textResp(http.StatusOK, "accounts-ok"),
		textResp(http.StatusTooManyRequests, `{"error":"slow_down","error_description":"Too many device code requests"}`),
		deviceCodeResp("dc", "UC", verifyURL),
		textResp(http.StatusOK, "verify-page"),
		found("https://accounts.x.ai/oauth2/consent"),
		textResp(http.StatusOK, "consent"),
		found("https://accounts.x.ai/oauth2/device/done"),
		textResp(http.StatusOK, "done"),
		pendingTokenResp(),
		tokenOKResp(),
	}}
	flow := &ssoBuildFlow{
		client: client, userAgent: "test-agent",
		cookies: map[string]string{"sso": "secret"},
		sleep:   instantSleep,
	}
	if _, err := flow.convert(context.Background(), accountdomain.Credential{Name: "web"}); err != nil {
		t.Fatal(err)
	}
}

func TestSSOBuildPollTokenContinuesOnTransientNetworkError(t *testing.T) {
	client := &scriptedSSOClient{
		responses: []*http.Response{tokenOKResp()},
		errOn:     map[int]error{1: io.EOF},
	}
	flow := &ssoBuildFlow{client: client, userAgent: "test-agent", cookies: map[string]string{"sso": "x"}, sleep: instantSleep}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	token, err := flow.pollToken(ctx, "dc", time.Second, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "access-ok" {
		t.Fatalf("token = %#v", token)
	}
	if client.calls.Load() < 2 {
		t.Fatalf("calls = %d, want at least 2 (eof then ok)", client.calls.Load())
	}
}

func TestSSOBuildTokenPollCapIsTwoMinutes(t *testing.T) {
	if ssoBuildTokenPollCap != 120*time.Second {
		t.Fatalf("poll cap = %s, want 120s", ssoBuildTokenPollCap)
	}
	if ssoBuildMaxRetries != 6 {
		t.Fatalf("max retries = %d, want 6", ssoBuildMaxRetries)
	}
	if ssoBuildConversionTimeout != 3*time.Minute {
		t.Fatalf("conversion timeout = %s, want 3m", ssoBuildConversionTimeout)
	}
}
