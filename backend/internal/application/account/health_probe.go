package account

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/pkg/batch"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

// HealthProbeStatus 账号测活结果状态。
type HealthProbeStatus string

const (
	HealthProbeHealthy      HealthProbeStatus = "healthy"
	HealthProbeUnauthorized HealthProbeStatus = "unauthorized"
	HealthProbePayment      HealthProbeStatus = "payment"
	HealthProbeForbidden    HealthProbeStatus = "forbidden"
	HealthProbeRateLimited  HealthProbeStatus = "rate_limited"
	HealthProbeNetwork      HealthProbeStatus = "network"
	HealthProbeError        HealthProbeStatus = "error"
	HealthProbeUnknown      HealthProbeStatus = "unknown"
)

const (
	maxHealthProbeAccounts     = 10000
	healthProbeRequestTimeout  = 20 * time.Second
)

// HealthProbeItem 单个账号测活结果。
type HealthProbeItem struct {
	AccountID  uint64
	Name       string
	Email      string
	Enabled    bool
	HTTPStatus int
	Status     HealthProbeStatus
	Error      string
	ElapsedMs  int64
	// Refreshed 表示测活过程中因 401 触发了 OAuth 凭据重刷，且刷新本身成功。
	// 最终 Status 可能仍为 unauthorized（重刷后上游仍拒绝）。
	Refreshed bool
}

// HealthProbeSummary 测活汇总。
type HealthProbeSummary struct {
	Total        int
	Healthy      int
	Unauthorized int
	Payment      int
	Forbidden    int
	RateLimited  int
	Network      int
	Error        int
	Unknown      int
	// Refreshed 表示因 401 自动重刷成功的账号数（含重刷后仍 401）。
	Refreshed int
	Items     []HealthProbeItem
}

// HealthProbeObserver 在每个账号测活结束后回调（completed 从 1 递增）。
type HealthProbeObserver func(item HealthProbeItem, completed, total int) error

// ProbeBuildHealth 并发探测全部 Grok Build 账号的上游可用性。
// 遇 HTTP 401 时会自动强制刷新 OAuth 凭据并复测一次（与网关运行时恢复一致）。
func (s *Service) ProbeBuildHealth(ctx context.Context, observer HealthProbeObserver) (HealthProbeSummary, error) {
	return s.ProbeBuildHealthWithProgress(ctx, observer, nil)
}

// ProbeBuildHealthWithProgress 并发探测并报告进度。
// 对返回 401 且可刷新的账号会写入新 token；刷新后仍 401 会标记 reauthRequired。
func (s *Service) ProbeBuildHealthWithProgress(ctx context.Context, observer HealthProbeObserver, progress BatchProgressObserver) (HealthProbeSummary, error) {
	adapter, err := s.buildProbeAdapter()
	if err != nil {
		return HealthProbeSummary{}, err
	}
	values, total, err := s.accounts.List(ctx, repository.AccountListQuery{
		Page:   repository.PageQuery{Limit: maxHealthProbeAccounts + 1},
		Filter: repository.AccountListFilter{Provider: string(accountdomain.ProviderBuild), Now: s.now()},
	})
	if err != nil {
		return HealthProbeSummary{}, err
	}
	if total > maxHealthProbeAccounts {
		return HealthProbeSummary{}, fmt.Errorf("%w: 单次最多测活 10000 个账号", ErrInvalidInput)
	}
	if progress != nil {
		if err := progress(0, len(values)); err != nil {
			return HealthProbeSummary{}, err
		}
	}

	items := make([]HealthProbeItem, len(values))
	var progressMu sync.Mutex
	var progressErr error
	completed := 0
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	pool := s.syncPool
	if pool == nil {
		pool = batch.NewPool(25)
	}
	results, summary, err := batch.MapObserved(runCtx, values, batch.Options{Workers: pool.Limit(), Pool: pool}, func(workCtx context.Context, value accountdomain.Credential) (HealthProbeItem, error) {
		return s.probeOneBuildAccount(workCtx, adapter, value), nil
	}, func(index int, result batch.Result[HealthProbeItem]) {
		item := result.Value
		if result.Err != nil {
			var panicErr *batch.PanicError
			if errors.As(result.Err, &panicErr) {
				s.logger.Error("account_health_probe_panicked", "account_id", values[index].ID, "error", panicErr, "stack", string(panicErr.Stack))
				item = HealthProbeItem{
					AccountID: values[index].ID, Name: values[index].Name, Email: values[index].Email, Enabled: values[index].Enabled,
					Status: HealthProbeError, Error: "测活任务异常",
				}
			} else {
				item = HealthProbeItem{
					AccountID: values[index].ID, Name: values[index].Name, Email: values[index].Email, Enabled: values[index].Enabled,
					Status: HealthProbeError, Error: result.Err.Error(),
				}
			}
		}
		items[index] = item
		progressMu.Lock()
		defer progressMu.Unlock()
		completed++
		if progress != nil {
			if notifyErr := progress(completed, len(values)); notifyErr != nil && progressErr == nil {
				progressErr = notifyErr
				cancel()
			}
		}
		if observer != nil && progressErr == nil {
			if notifyErr := observer(item, completed, len(values)); notifyErr != nil && progressErr == nil {
				progressErr = notifyErr
				cancel()
			}
		}
	})
	_ = results
	s.logBatchSummary("health_probe", pool, summary, err)

	out := HealthProbeSummary{Total: len(items), Items: items}
	for _, item := range items {
		if item.Refreshed {
			out.Refreshed++
		}
		switch item.Status {
		case HealthProbeHealthy:
			out.Healthy++
		case HealthProbeUnauthorized:
			out.Unauthorized++
		case HealthProbePayment:
			out.Payment++
		case HealthProbeForbidden:
			out.Forbidden++
		case HealthProbeRateLimited:
			out.RateLimited++
		case HealthProbeNetwork:
			out.Network++
		case HealthProbeError:
			out.Error++
		default:
			out.Unknown++
		}
	}
	return out, errors.Join(err, progressErr)
}

type buildHealthProber interface {
	ProbeResponses(ctx context.Context, credential accountdomain.Credential, accessToken string) (int, error)
}

func (s *Service) buildProbeAdapter() (buildHealthProber, error) {
	if s.providers == nil {
		return nil, fmt.Errorf("Provider 注册表未初始化")
	}
	adapter, ok := s.providers.Get(accountdomain.ProviderBuild)
	if !ok {
		return nil, fmt.Errorf("CLI Provider 未注册")
	}
	prober, ok := adapter.(buildHealthProber)
	if !ok {
		return nil, fmt.Errorf("CLI Provider 不支持测活")
	}
	return prober, nil
}

func (s *Service) probeOneBuildAccount(ctx context.Context, adapter buildHealthProber, value accountdomain.Credential) HealthProbeItem {
	item := HealthProbeItem{
		AccountID: value.ID,
		Name:      value.Name,
		Email:     value.Email,
		Enabled:   value.Enabled,
	}
	started := time.Now()
	accessToken, err := s.cipher.Decrypt(value.EncryptedAccessToken)
	if err != nil {
		item.Status = HealthProbeError
		item.Error = "读取 access token 失败"
		item.ElapsedMs = time.Since(started).Milliseconds()
		return item
	}
	if strings.TrimSpace(accessToken) == "" {
		item.Status = HealthProbeError
		item.Error = "access token 为空"
		item.ElapsedMs = time.Since(started).Milliseconds()
		return item
	}

	probeCtx, cancel := context.WithTimeout(ctx, healthProbeRequestTimeout)
	statusCode, err := adapter.ProbeResponses(probeCtx, value, accessToken)
	cancel()
	item.HTTPStatus = statusCode
	item.Status, item.Error = classifyHealthProbe(statusCode, err)

	// 401 时自动强制 OAuth 重刷并复测，对齐网关运行时恢复与 grok-manager 的 401 重刷流水线。
	if item.Status == HealthProbeUnauthorized {
		item = s.recoverUnauthorizedBuildProbe(ctx, adapter, value, item)
	}

	item.ElapsedMs = time.Since(started).Milliseconds()
	return item
}

// recoverUnauthorizedBuildProbe 在首次测活 401 后尝试刷新凭据并复测。
// 刷新成功后若仍 401，标记 reauthRequired 并退出号池。
func (s *Service) recoverUnauthorizedBuildProbe(ctx context.Context, adapter buildHealthProber, value accountdomain.Credential, item HealthProbeItem) HealthProbeItem {
	if s.providers == nil || !s.providers.SupportsCredentialRefresh(value.Provider) || strings.TrimSpace(value.EncryptedRefreshToken) == "" {
		item.Error = "HTTP 401（无可用 refresh token，无法自动重刷）"
		return item
	}
	if ctx.Err() != nil {
		item.Status = HealthProbeNetwork
		item.Error = truncateProbeError(ctx.Err().Error())
		return item
	}

	// 测活路径绕过进程内强制刷新节流，确保诊断结果反映当前可恢复性。
	refreshed, refreshErr := s.ensureCredential(ctx, value, true, true, false)
	if refreshErr != nil {
		item.Error = "HTTP 401，自动重刷失败: " + truncateProbeError(refreshErr.Error())
		return item
	}
	item.Refreshed = true

	accessToken, err := s.cipher.Decrypt(refreshed.EncryptedAccessToken)
	if err != nil || strings.TrimSpace(accessToken) == "" {
		item.Status = HealthProbeError
		item.Error = "重刷成功但读取新 access token 失败"
		return item
	}

	probeCtx, cancel := context.WithTimeout(ctx, healthProbeRequestTimeout)
	statusCode, err := adapter.ProbeResponses(probeCtx, refreshed, accessToken)
	cancel()
	item.HTTPStatus = statusCode
	item.Status, item.Error = classifyHealthProbe(statusCode, err)
	if item.Status == HealthProbeUnauthorized {
		item.Error = "HTTP 401（已重刷，上游仍拒绝）"
		// 刷新后仍被拒说明 refresh token 也已失效，与网关行为一致标记 reauth。
		if markErr := s.MarkReauthRequired(context.WithoutCancel(ctx), value.ID, "Grok Build OAuth credential rejected after health-probe refresh"); markErr != nil {
			s.logger.Warn("health_probe_reauth_mark_failed", "account_id", value.ID, "error", markErr)
		}
		return item
	}
	if item.Status == HealthProbeHealthy {
		item.Error = "已自动重刷"
	} else if item.Error != "" {
		item.Error = "已自动重刷后: " + item.Error
	} else {
		item.Error = "已自动重刷"
	}
	return item
}

func classifyHealthProbe(httpStatus int, err error) (HealthProbeStatus, string) {
	if err != nil {
		if isHealthProbeNetworkError(err) {
			return HealthProbeNetwork, truncateProbeError(err.Error())
		}
		return HealthProbeError, truncateProbeError(err.Error())
	}
	switch {
	case httpStatus >= 200 && httpStatus < 300:
		return HealthProbeHealthy, ""
	case httpStatus == http.StatusUnauthorized:
		return HealthProbeUnauthorized, "HTTP 401"
	case httpStatus == http.StatusPaymentRequired:
		return HealthProbePayment, "HTTP 402"
	case httpStatus == http.StatusForbidden:
		return HealthProbeForbidden, "HTTP 403"
	case httpStatus == http.StatusTooManyRequests:
		return HealthProbeRateLimited, "HTTP 429"
	case httpStatus == 0:
		return HealthProbeUnknown, "无 HTTP 状态"
	default:
		return HealthProbeUnknown, "HTTP " + strconv.Itoa(httpStatus)
	}
}

func isHealthProbeNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, token := range []string{"timeout", "timed out", "connection refused", "connection reset", "no such host", "network is unreachable", "i/o timeout", "tls handshake", "eof"} {
		if strings.Contains(message, token) {
			return true
		}
	}
	return false
}

func truncateProbeError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 240 {
		return value
	}
	return value[:240]
}
