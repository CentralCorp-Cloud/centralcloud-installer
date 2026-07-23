package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(_ context.Context, duration time.Duration) error {
	c.now = c.now.Add(duration)
	return nil
}

func TestPollPendingSlowDownThenApproval(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(apiError{Error: "authorization_pending"})
		case 2:
			w.WriteHeader(429)
			_ = json.NewEncoder(w).Encode(apiError{Error: "slow_down"})
		default:
			_ = json.NewEncoder(w).Encode(Approved{Status: "approved", BootstrapToken: "bootstrap"})
		}
	}))
	defer server.Close()
	clock := &fakeClock{now: time.Unix(0, 0)}
	result, err := (Client{BaseURL: server.URL, HTTP: server.Client(), Clock: clock}).Poll(context.Background(), DeviceAuthorization{DeviceCode: "device", ExpiresIn: 60, Interval: 5})
	if err != nil || result.Status != "approved" || requests != 3 {
		t.Fatalf("result=%#v requests=%d err=%v", result, requests, err)
	}
}

func TestPollDenial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(apiError{Error: "access_denied"})
	}))
	defer server.Close()
	_, err := (Client{BaseURL: server.URL, HTTP: server.Client(), Clock: &fakeClock{now: time.Unix(0, 0)}}).Poll(context.Background(), DeviceAuthorization{DeviceCode: "device", ExpiresIn: 10, Interval: 5})
	if err == nil {
		t.Fatal("expected denial")
	}
}
