package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/detection"
)

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }
func (RealClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type Client struct {
	BaseURL string
	HTTP    *http.Client
	Clock   Clock
}

type DeviceAuthorization struct {
	EnrollmentID            string `json:"enrollment_id"`
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	CorrelationID           string `json:"correlation_id"`
}

type Approved struct {
	Status             string `json:"status"`
	EnrollmentID       string `json:"enrollment_id"`
	BootstrapToken     string `json:"bootstrap_token"`
	BootstrapExpiresIn int    `json:"bootstrap_expires_in"`
	Node               struct {
		ID                string `json:"id"`
		Name              string `json:"name"`
		FQDN              string `json:"fqdn"`
		Endpoint          string `json:"endpoint"`
		Environment       string `json:"environment"`
		Region            string `json:"region"`
		PanelDomainSuffix string `json:"panel_domain_suffix"`
	} `json:"node"`
	Agent struct {
		Version         string `json:"version"`
		Channel         string `json:"channel"`
		ProtocolVersion string `json:"protocol_version"`
		ManifestURL     string `json:"manifest_url"`
		Authentication  struct {
			Mode  string `json:"mode"`
			Token string `json:"token"`
		} `json:"authentication"`
	} `json:"agent"`
	Security struct {
		AllowedClientSANs  []string `json:"allowed_client_sans"`
		AllowedSourceCIDRs []string `json:"allowed_source_cidrs"`
	} `json:"security"`
}

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (c Client) Create(ctx context.Context, host detection.Host) (DeviceAuthorization, error) {
	var response DeviceAuthorization
	err := c.request(ctx, http.MethodPost, "/api/v1/node-enrollments/device", "", host, &response)
	return response, err
}

func (c Client) Automatic(ctx context.Context, host detection.Host, token []byte) (Approved, error) {
	var response Approved
	err := c.request(ctx, http.MethodPost, "/api/v1/node-enrollments/automatic", string(token), host, &response)
	return response, err
}

func (c Client) Poll(ctx context.Context, auth DeviceAuthorization) (Approved, error) {
	if c.Clock == nil {
		c.Clock = RealClock{}
	}
	deadline := c.Clock.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	interval := time.Duration(auth.Interval) * time.Second
	for c.Clock.Now().Before(deadline) {
		if err := c.Clock.Sleep(ctx, interval); err != nil {
			return Approved{}, err
		}
		var approved Approved
		var remote apiError
		status, err := c.raw(ctx, http.MethodPost, "/api/v1/node-enrollments/device/token", "", map[string]string{"device_code": auth.DeviceCode}, &approved, &remote)
		if err != nil {
			return Approved{}, err
		}
		if status == http.StatusOK {
			return approved, nil
		}
		switch remote.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			if interval > 30*time.Second {
				interval = 30 * time.Second
			}
		case "access_denied":
			return Approved{}, errors.New("enrollment denied")
		case "expired_token":
			return Approved{}, errors.New("enrollment expired")
		default:
			return Approved{}, fmt.Errorf("enrollment API: %s", remote.Error)
		}
	}
	return Approved{}, errors.New("enrollment expired")
}

func (c Client) Progress(ctx context.Context, id, token, key, step string, percent int, message string) error {
	var ignored map[string]any
	return c.requestWithKey(ctx, "/api/v1/node-enrollments/"+id+"/progress", token, key, map[string]any{"step": step, "percentage": percent, "message": message}, &ignored)
}

type Certificate struct {
	Certificate        string   `json:"certificate"`
	Chain              string   `json:"chain"`
	ClientCA           string   `json:"client_ca"`
	AllowedClientSANs  []string `json:"allowed_client_sans"`
	AllowedSourceCIDRs []string `json:"allowed_source_cidrs"`
	ExpiresAt          string   `json:"expires_at"`
}

func (c Client) Certificate(ctx context.Context, id, token, key string, csr []byte) (Certificate, error) {
	var response Certificate
	err := c.requestWithKey(ctx, "/api/v1/node-enrollments/"+id+"/certificate", token, key, map[string]string{"csr": string(csr)}, &response)
	return response, err
}

func (c Client) Complete(ctx context.Context, id, token, key string, report any) (map[string]any, error) {
	var response map[string]any
	err := c.requestWithKey(ctx, "/api/v1/node-enrollments/"+id+"/complete", token, key, report, &response)
	return response, err
}

func (c Client) requestWithKey(ctx context.Context, path, token, key string, body, output any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", key)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var remote apiError
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&remote)
		return fmt.Errorf("%s: %s", remote.Error, remote.Message)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(output)
}

func (c Client) request(ctx context.Context, method, path, token string, body, output any) error {
	var remote apiError
	status, err := c.raw(ctx, method, path, token, body, output, &remote)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("%s: %s", remote.Error, remote.Message)
	}
	return nil
}

func (c Client) raw(ctx context.Context, method, path, token string, body, output any, remote *apiError) (int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, decoder.Decode(output)
	}
	if err := decoder.Decode(remote); err != nil {
		return resp.StatusCode, fmt.Errorf("decode API error: %w", err)
	}
	return resp.StatusCode, nil
}
