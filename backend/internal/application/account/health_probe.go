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
	Items        []HealthProbeItem
}

// HealthProbeObserver 在每个账号测活结束后回调（completed 从 1 递增）。
type HealthProbeObserver func(item HealthProbeItem, completed, total int) error

// ProbeBuildHealth 并发探测全部 Grok Build 账号的上游可用性。
// 只读诊断，不修改账号健康度或凭据状态。
func (s *Service) ProbeBuildHealth(ctx context.Context, observer HealthProbeObserver) (HealthProbeSummary, error) {
	return s.ProbeBuildHealthWithProgress(ctx, observer, nil)
}

// ProbeBuildHealthWithProgress 并发探测并报告进度。
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
	defer cancel()
	statusCode, err := adapter.ProbeResponses(probeCtx, value, accessToken)
	item.ElapsedMs = time.Since(started).Milliseconds()
	item.HTTPStatus = statusCode
	item.Status, item.Error = classifyHealthProbe(statusCode, err)
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
