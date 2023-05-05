package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type ClientConfig struct {
	SkipTLSVerify bool
	BaseURL       string
	ProxyString   string
}

type Client struct {
	baseURL    string
	apiKey     string
	HTTPClient *http.Client
}

type Response struct {
	Data   interface{}            `json:"data,omitempty"`
	Errors map[string]interface{} `json:"errors,omitempty"`
}

func NewClient(cfg *ClientConfig) (client *Client, err error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}
	httpTransport := &http.Transport{TLSClientConfig: tlsConfig}

	if cfg.ProxyString != "" {
		proxyURL, err := url.ParseRequestURI(cfg.ProxyString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy string: %w", err)
		}
		httpTransport.Proxy = http.ProxyURL(proxyURL)
	}

	httpClient := &http.Client{Transport: httpTransport}

	return &Client{
		baseURL:    cfg.BaseURL,
		HTTPClient: httpClient,
	}, nil
}

func (c *Client) SetAPIToken(userID, token string) {
	authString := fmt.Sprintf("%s=%s", userID, token)
	c.apiKey = authString
}

func (c *Client) setRequestHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s", c.apiKey))
}

func (*Client) buildResponseError(status string, resBody Response) error {
	errorMsg := fmt.Sprintf("API returned status: %s", status)

	if len(resBody.Errors) > 0 {
		errorMsg += " With error(s): "
		for k, v := range resBody.Errors {
			errorMsg += fmt.Sprintf("%s: %s, ", k, v)
		}
		errorMsg = strings.TrimSuffix(errorMsg, ", ")
	}
	return fmt.Errorf(errorMsg)
}

func (c *Client) SendRequest(ctx context.Context, method string, apiPath string, body io.Reader, v interface{}) error {
	url := c.baseURL + apiPath

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("failed to create an http request: %w", err)
	}

	c.setRequestHeaders(req)
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send http request: %w", err)
	}

	defer res.Body.Close()
	resBody := Response{Data: v}
	if err := json.NewDecoder(res.Body).Decode(&resBody); err != nil {
		return fmt.Errorf("API Response Status: %s. failed to decode json response: %w", res.Status, err)
	}

	if res.StatusCode >= http.StatusBadRequest {
		return c.buildResponseError(res.Status, resBody)
	}
	return nil
}
