package account

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestClassifyHealthProbe(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		err    error
		want   HealthProbeStatus
	}{
		{"ok", 200, nil, HealthProbeHealthy},
		{"created", 201, nil, HealthProbeHealthy},
		{"unauthorized", 401, nil, HealthProbeUnauthorized},
		{"payment", 402, nil, HealthProbePayment},
		{"forbidden", 403, nil, HealthProbeForbidden},
		{"rate", 429, nil, HealthProbeRateLimited},
		{"unknown", 500, nil, HealthProbeUnknown},
		{"deadline", 0, context.DeadlineExceeded, HealthProbeNetwork},
		{"net", 0, &net.OpError{Op: "dial", Err: errors.New("connection refused")}, HealthProbeNetwork},
		{"local", 0, errors.New("decrypt failed"), HealthProbeError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := classifyHealthProbe(tc.status, tc.err)
			if got != tc.want {
				t.Fatalf("status=%v want=%v got=%v", tc.status, tc.want, got)
			}
		})
	}
}

func TestIsHealthProbeNetworkError(t *testing.T) {
	t.Parallel()
	if !isHealthProbeNetworkError(context.DeadlineExceeded) {
		t.Fatal("deadline should be network")
	}
	if isHealthProbeNetworkError(errors.New("decrypt failed")) {
		t.Fatal("local error should not be network")
	}
	if !isHealthProbeNetworkError(errors.New("dial tcp: i/o timeout")) {
		t.Fatal("timeout string should be network")
	}
	if !isHealthProbeNetworkError(&net.DNSError{Err: "no such host", Name: "example.invalid", IsNotFound: true}) {
		t.Fatal("dns error should be network")
	}
	_ = http.StatusOK
	_ = time.Second
}
