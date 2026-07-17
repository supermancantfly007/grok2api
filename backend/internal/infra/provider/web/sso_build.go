package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
)

const (
	ssoBuildClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	ssoBuildScope    = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write"
	ssoAccountsURL   = "https://accounts.x.ai/"
	ssoDeviceURL     = "https://auth.x.ai/oauth2/device/code"
	ssoVerifyURL     = "https://auth.x.ai/oauth2/device/verify"
	ssoApproveURL    = "https://auth.x.ai/oauth2/device/approve"
	ssoTokenURL      = "https://auth.x.ai/oauth2/token"
	maxAuthBody      = 2 << 20

	// 对齐 Grok Manager 的批量 SSO 转换鲁棒性；并发仍由 account.conversionPool 控制。
	ssoBuildMaxRetries         = 6
	ssoBuildConversionTimeout  = 3 * time.Minute
	ssoBuildTokenPollCap       = 120 * time.Second
	ssoBuildBackoffBase        = 10 * time.Second
	ssoBuildBackoffCap         = 90 * time.Second
)

type ssoBuildHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type ssoBuildFlow struct {
	client    ssoBuildHTTPClient
	userAgent string
	cookies   map[string]string
	// sleep 可注入，测试中置为立即返回以避免真实等待。
	sleep func(context.Context, time.Duration) error
}

func (a *Adapter) ConvertToBuild(ctx context.Context, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	if credential.Provider != accountdomain.ProviderWeb || credential.AuthType != accountdomain.AuthTypeSSO {
		return provider.CredentialSeed{}, fmt.Errorf("仅 Grok Web SSO 账号支持转换")
	}
	token, err := a.cipher.Decrypt(credential.EncryptedAccessToken)
	if err != nil {
		return provider.CredentialSeed{}, fmt.Errorf("解密 Grok Web SSO: %w", err)
	}
	token = normalizeSSOToken(token)
	if token == "" {
		return provider.CredentialSeed{}, provider.ErrUnauthorized
	}
	lease, err := a.egress.AcquireCredential(ctx, egressdomain.ScopeWeb, credential)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	defer lease.Release()
	requestCtx, cancel := context.WithTimeout(ctx, ssoBuildConversionTimeout)
	defer cancel()
	flow := &ssoBuildFlow{
		client: lease, userAgent: lease.UserAgent,
		cookies: map[string]string{"sso": token, "sso-rw": token},
	}
	seed, err := flow.convert(requestCtx, credential)
	if err != nil {
		a.egress.Feedback(context.WithoutCancel(ctx), lease.NodeID, conversionStatus(err), err)
		return provider.CredentialSeed{}, err
	}
	a.egress.Feedback(context.WithoutCancel(ctx), lease.NodeID, http.StatusOK, nil)
	return seed, nil
}

type deviceAuthorization struct {
	DeviceCode              string
	UserCode                string
	VerificationURIComplete string
	Interval                int
	ExpiresIn               int
}

func (f *ssoBuildFlow) convert(ctx context.Context, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	status, finalURL, _, err := f.do(ctx, http.MethodGet, ssoAccountsURL, nil)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	lowURL := strings.ToLower(finalURL)
	if status == http.StatusUnauthorized || strings.Contains(lowURL, "sign-in") || strings.Contains(lowURL, "sign-up") || strings.Contains(lowURL, "login") {
		return provider.CredentialSeed{}, provider.ErrUnauthorized
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("校验 Grok Web SSO 失败: %w", conversionHTTPError{status: status})
	}

	var device deviceAuthorization
	freshDevice := func() error {
		next, err := f.requestDevice(ctx)
		if err != nil {
			return err
		}
		device = next
		status, _, _, err := f.do(ctx, http.MethodGet, device.VerificationURIComplete, nil)
		if err != nil {
			return fmt.Errorf("打开 Device Flow 验证页失败: %w", err)
		}
		if status < 200 || status >= 400 {
			return fmt.Errorf("打开 Device Flow 验证页失败: %w", conversionHTTPError{status: status})
		}
		return nil
	}

	if err := f.requestDeviceWithRetry(ctx, freshDevice); err != nil {
		return provider.CredentialSeed{}, err
	}

	rateHits := 0
	approveOK := false
	for attempt := 1; attempt <= ssoBuildMaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return provider.CredentialSeed{}, err
		}

		status, finalURL, body, err := f.do(ctx, http.MethodPost, ssoVerifyURL, url.Values{"user_code": {device.UserCode}})
		if err != nil {
			if sleepErr := f.backoff(ctx, attempt); sleepErr != nil {
				return provider.CredentialSeed{}, sleepErr
			}
			continue
		}
		if isSSOConversionRateLimited(status, finalURL, string(body)) {
			rateHits++
			if sleepErr := f.backoff(ctx, attempt); sleepErr != nil {
				return provider.CredentialSeed{}, sleepErr
			}
			if err := freshDevice(); err != nil {
				return provider.CredentialSeed{}, err
			}
			continue
		}
		// 对齐 GM：无 consent 且 status>=400 才硬失败；2xx 即使无 consent 也继续 approve。
		if status >= 400 && !strings.Contains(strings.ToLower(finalURL+" "+string(body)), "consent") {
			return provider.CredentialSeed{}, fmt.Errorf("SSO 自动验证 Device Flow 失败: %w", conversionHTTPError{status: status})
		}

		status, finalURL, body, err = f.do(ctx, http.MethodPost, ssoApproveURL, url.Values{
			"user_code": {device.UserCode}, "action": {"allow"}, "principal_type": {"User"}, "principal_id": {""},
		})
		if err != nil {
			if sleepErr := f.backoff(ctx, attempt); sleepErr != nil {
				return provider.CredentialSeed{}, sleepErr
			}
			continue
		}
		if isSSOConversionRateLimited(status, finalURL, string(body)) {
			rateHits++
			if sleepErr := f.backoff(ctx, attempt); sleepErr != nil {
				return provider.CredentialSeed{}, sleepErr
			}
			if err := freshDevice(); err != nil {
				return provider.CredentialSeed{}, err
			}
			continue
		}
		// 对齐 GM：status>=400 且 URL 不含 done 才失败；落到 done 即视为批准成功。
		if status >= 400 && !strings.Contains(strings.ToLower(finalURL), "done") {
			return provider.CredentialSeed{}, fmt.Errorf("SSO 自动批准 Device Flow 失败: %w", conversionHTTPError{status: status})
		}
		approveOK = true
		break
	}
	if !approveOK {
		if rateHits > 0 {
			return provider.CredentialSeed{}, fmt.Errorf("SSO 自动批准 Device Flow 限流重试耗尽")
		}
		return provider.CredentialSeed{}, fmt.Errorf("SSO 自动批准 Device Flow 失败")
	}

	token, err := f.pollToken(ctx, device.DeviceCode, time.Duration(device.Interval)*time.Second, time.Duration(device.ExpiresIn)*time.Second)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	claims := decodeBuildClaims(firstValue(token.IDToken, token.AccessToken))
	userID := claimString(claims, "sub")
	email := claimString(claims, "email")
	teamID := claimString(claims, "team_id")
	name := strings.TrimSpace(credential.Name)
	if name == "" {
		name = "Grok Web account"
	}
	return provider.CredentialSeed{
		Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth,
		Name: firstValue(email, name+" Build", userID, "Grok Build account"), Email: email, UserID: userID, TeamID: teamID,
		SourceKey: "sso-build:" + security.HashToken(token.AccessToken), OIDCClientID: ssoBuildClientID,
		AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAt: token.ExpiresAt,
	}, nil
}

func (f *ssoBuildFlow) requestDeviceWithRetry(ctx context.Context, freshDevice func() error) error {
	var lastErr error
	for attempt := 1; attempt <= ssoBuildMaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := freshDevice()
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableSSOConversionError(err) && !errors.Is(err, context.DeadlineExceeded) {
			// 非限流/瞬时错误：仍允许网络类错误重试。
			if !isTransientSSOConversionError(err) {
				return err
			}
		}
		if sleepErr := f.backoff(ctx, attempt); sleepErr != nil {
			return sleepErr
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("xAI Device Flow 启动失败")
}

func (f *ssoBuildFlow) requestDevice(ctx context.Context) (deviceAuthorization, error) {
	form := url.Values{"client_id": {ssoBuildClientID}, "scope": {ssoBuildScope}}
	status, _, body, err := f.do(ctx, http.MethodPost, ssoDeviceURL, form)
	if err != nil {
		return deviceAuthorization{}, err
	}
	if status == http.StatusTooManyRequests || isSSOConversionRateLimited(status, "", string(body)) {
		return deviceAuthorization{}, fmt.Errorf("xAI Device Flow 启动限流: %w", conversionHTTPError{status: status})
	}
	if status < 200 || status >= 300 {
		return deviceAuthorization{}, fmt.Errorf("xAI Device Flow 启动失败: %w", conversionHTTPError{status: status})
	}
	var device struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		Interval                int    `json:"interval"`
		ExpiresIn               int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &device); err != nil {
		return deviceAuthorization{}, fmt.Errorf("解析 xAI Device Flow: %w", err)
	}
	if device.DeviceCode == "" || device.UserCode == "" || !safeXAIURL(device.VerificationURIComplete) {
		return deviceAuthorization{}, fmt.Errorf("xAI Device Flow 返回字段不完整")
	}
	if device.Interval <= 0 {
		device.Interval = 5
	}
	if device.ExpiresIn <= 0 {
		device.ExpiresIn = 1800
	}
	return deviceAuthorization{
		DeviceCode: device.DeviceCode, UserCode: device.UserCode,
		VerificationURIComplete: device.VerificationURIComplete,
		Interval:                device.Interval, ExpiresIn: device.ExpiresIn,
	}, nil
}

type ssoBuildToken struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresAt    time.Time
}

func (f *ssoBuildFlow) pollToken(ctx context.Context, deviceCode string, interval, expiresIn time.Duration) (ssoBuildToken, error) {
	if interval < time.Second {
		interval = time.Second
	}
	deadline := time.Now().Add(min(expiresIn, ssoBuildTokenPollCap))
	for time.Now().Before(deadline) {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ssoBuildToken{}, ctx.Err()
		case <-timer.C:
		}
		status, _, body, err := f.do(ctx, http.MethodPost, ssoTokenURL, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {ssoBuildClientID}, "device_code": {deviceCode},
		})
		if err != nil {
			// 对齐 GM：轮询阶段网络抖动不立刻失败。
			continue
		}
		var payload struct {
			AccessToken      string `json:"access_token"`
			RefreshToken     string `json:"refresh_token"`
			IDToken          string `json:"id_token"`
			ExpiresIn        int    `json:"expires_in"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return ssoBuildToken{}, fmt.Errorf("解析 xAI OAuth Token: %w", err)
		}
		if status >= 200 && status < 300 && payload.AccessToken != "" {
			if payload.ExpiresIn <= 0 {
				payload.ExpiresIn = 3600
			}
			return ssoBuildToken{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, IDToken: payload.IDToken, ExpiresAt: time.Now().UTC().Add(time.Duration(payload.ExpiresIn) * time.Second)}, nil
		}
		switch payload.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied", "expired_token":
			return ssoBuildToken{}, provider.ErrAuthorizationDenied
		default:
			if status >= 400 {
				return ssoBuildToken{}, fmt.Errorf("xAI OAuth Token 失败 (%s): %w", firstValue(payload.ErrorDescription, payload.Error), conversionHTTPError{status: status})
			}
			return ssoBuildToken{}, fmt.Errorf("xAI OAuth Token 失败: %s", firstValue(payload.ErrorDescription, payload.Error, strconv.Itoa(status)))
		}
	}
	return ssoBuildToken{}, fmt.Errorf("xAI Device Flow 轮询超时")
}

func (f *ssoBuildFlow) do(ctx context.Context, method, endpoint string, form url.Values) (int, string, []byte, error) {
	if !safeXAIURL(endpoint) {
		return 0, "", nil, fmt.Errorf("xAI OAuth URL 不安全")
	}
	currentURL := endpoint
	currentMethod := method
	currentForm := form
	for redirects := 0; redirects <= 8; redirects++ {
		var body io.Reader
		if currentForm != nil {
			body = strings.NewReader(currentForm.Encode())
		}
		request, err := http.NewRequestWithContext(ctx, currentMethod, currentURL, body)
		if err != nil {
			return 0, "", nil, err
		}
		request.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
		request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
		request.Header.Set("User-Agent", f.userAgent)
		request.Header.Set("Cookie", f.cookieHeader())
		if currentForm != nil {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		response, err := f.client.Do(request)
		if err != nil {
			return 0, "", nil, err
		}
		f.captureCookies(response)
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxAuthBody+1))
		_ = response.Body.Close()
		if readErr != nil {
			return response.StatusCode, currentURL, nil, readErr
		}
		if len(data) > maxAuthBody {
			return response.StatusCode, currentURL, nil, fmt.Errorf("xAI OAuth 响应超过 2 MiB")
		}
		if response.StatusCode < 300 || response.StatusCode > 399 {
			return response.StatusCode, currentURL, data, nil
		}
		location := strings.TrimSpace(response.Header.Get("Location"))
		if location == "" {
			return response.StatusCode, currentURL, data, fmt.Errorf("xAI OAuth 重定向缺少 Location")
		}
		base, _ := url.Parse(currentURL)
		next, err := url.Parse(location)
		if err != nil {
			return response.StatusCode, currentURL, data, err
		}
		currentURL = base.ResolveReference(next).String()
		if !safeXAIURL(currentURL) {
			return response.StatusCode, currentURL, data, fmt.Errorf("xAI OAuth 重定向到非受信域名")
		}
		if response.StatusCode == http.StatusSeeOther || ((response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusFound) && currentMethod != http.MethodGet && currentMethod != http.MethodHead) {
			currentMethod = http.MethodGet
			currentForm = nil
		}
	}
	return 0, currentURL, nil, fmt.Errorf("xAI OAuth 重定向次数过多")
}

func (f *ssoBuildFlow) captureCookies(response *http.Response) {
	for _, cookie := range response.Cookies() {
		name := strings.TrimSpace(cookie.Name)
		value := strings.TrimSpace(cookie.Value)
		if name == "" || len(name) > 128 || len(value) > 16384 || strings.ContainsAny(name+value, "\r\n\x00") {
			continue
		}
		if cookie.MaxAge < 0 {
			delete(f.cookies, name)
			continue
		}
		f.cookies[name] = value
	}
}

func (f *ssoBuildFlow) cookieHeader() string {
	keys := make([]string, 0, len(f.cookies))
	for key := range f.cookies {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+f.cookies[key])
	}
	return strings.Join(parts, "; ")
}

func (f *ssoBuildFlow) backoff(ctx context.Context, attempt int) error {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 4 {
		shift = 4
	}
	delay := ssoBuildBackoffBase * time.Duration(1<<shift)
	if delay > ssoBuildBackoffCap {
		delay = ssoBuildBackoffCap
	}
	if f.sleep != nil {
		return f.sleep(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isSSOConversionRateLimited(status int, finalURL, body string) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	blob := strings.ToLower(finalURL + "\n" + body)
	for _, token := range []string{
		"rate_limited", "rate-limited", "too_many_requests", "ratelimit",
		`"status":429`, "slow_down", `"error":"slow_down"`,
	} {
		if strings.Contains(blob, token) {
			return true
		}
	}
	return false
}

func isRetryableSSOConversionError(err error) bool {
	if err == nil {
		return false
	}
	var statusErr conversionHTTPError
	if errors.As(err, &statusErr) && (statusErr.status == http.StatusTooManyRequests || statusErr.status == 0) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, token := range []string{"限流", "slow_down", "rate_limited", "too many", "429"} {
		if strings.Contains(message, token) {
			return true
		}
	}
	return false
}

func isTransientSSOConversionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, token := range []string{"timeout", "timed out", "connection reset", "connection refused", "eof", "broken pipe", "tls handshake", "i/o timeout", "temporary"} {
		if strings.Contains(message, token) {
			return true
		}
	}
	return false
}

func safeXAIURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "x.ai" || strings.HasSuffix(host, ".x.ai")
}

func normalizeSSOToken(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "sso=") {
		value = strings.TrimSpace(value[len("sso="):])
	}
	if token, _, found := strings.Cut(value, ";"); found {
		value = strings.TrimSpace(token)
	}
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(value)
}

func decodeBuildClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(data, &claims) != nil {
		return nil
	}
	return claims
}

func claimString(claims map[string]any, key string) string {
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}

func firstValue(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

type conversionHTTPError struct{ status int }

func (e conversionHTTPError) Error() string { return fmt.Sprintf("xAI OAuth HTTP %d", e.status) }

func conversionStatus(err error) int {
	var statusErr conversionHTTPError
	if errors.As(err, &statusErr) {
		return statusErr.status
	}
	if errors.Is(err, provider.ErrUnauthorized) {
		return http.StatusUnauthorized
	}
	return 0
}

var _ provider.BuildCredentialConverter = (*Adapter)(nil)
var _ ssoBuildHTTPClient = (*infraegress.Lease)(nil)
