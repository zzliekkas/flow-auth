package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// OAuth2Config OAuth2配置接口
type OAuth2Config interface {
	// AuthCodeURL 生成授权URL
	AuthCodeURL(state string, opts ...AuthCodeOption) string

	// Exchange 使用授权码交换访问令牌
	Exchange(ctx context.Context, code string) (*Token, error)

	// Client 返回一个配置了令牌的HTTP客户端
	Client(ctx context.Context, token *Token) *http.Client
}

// Token OAuth2令牌
type Token struct {
	// 访问令牌
	AccessToken string `json:"access_token"`

	// 令牌类型
	TokenType string `json:"token_type,omitempty"`

	// 刷新令牌
	RefreshToken string `json:"refresh_token,omitempty"`

	// 过期时间
	ExpiresIn int64 `json:"expires_in,omitempty"`

	// 作用域
	Scope string `json:"scope,omitempty"`

	// 原始响应
	Raw interface{} `json:"-"`
}

// AuthCodeOption 授权码选项
type AuthCodeOption interface {
	apply(*authCodeOptions)
}

// authCodeOptions 授权码选项
type authCodeOptions struct {
	// 额外参数
	extraParams url.Values
}

// WithAuthCodeParam 添加额外的授权参数
func WithAuthCodeParam(key, value string) AuthCodeOption {
	return authCodeOptionFunc(func(o *authCodeOptions) {
		if o.extraParams == nil {
			o.extraParams = make(url.Values)
		}
		o.extraParams.Add(key, value)
	})
}

type authCodeOptionFunc func(*authCodeOptions)

func (f authCodeOptionFunc) apply(o *authCodeOptions) {
	f(o)
}

// OAuth2Client OAuth2客户端
type OAuth2Client struct {
	// 客户端ID
	ClientID string

	// 客户端密钥
	ClientSecret string

	// 授权端点
	AuthURL string

	// 令牌端点
	TokenURL string

	// 重定向URL
	RedirectURL string

	// 作用域
	Scopes []string

	// HTTP客户端
	HTTPClient *http.Client
}

// NewOAuth2Client 创建新的OAuth2客户端
func NewOAuth2Client(config *OAuth2Client) *OAuth2Client {
	if config.HTTPClient == nil {
		config.HTTPClient = http.DefaultClient
	}
	return config
}

// AuthCodeURL 生成授权URL
func (c *OAuth2Client) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	var options authCodeOptions
	for _, opt := range opts {
		opt.apply(&options)
	}

	v := url.Values{
		"response_type": {"code"},
		"client_id":     {c.ClientID},
	}

	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}

	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}

	if state != "" {
		v.Set("state", state)
	}

	if options.extraParams != nil {
		for key, values := range options.extraParams {
			v[key] = values
		}
	}

	return c.AuthURL + "?" + v.Encode()
}

// Exchange 使用授权码交换访问令牌
func (c *OAuth2Client) Exchange(ctx context.Context, code string) (*Token, error) {
	v := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
	}

	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}

	return c.doTokenRequest(ctx, v)
}

// doTokenRequest 执行令牌请求
func (c *OAuth2Client) doTokenRequest(ctx context.Context, v url.Values) (*Token, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
}

// Client 返回一个配置了令牌的HTTP客户端
func (c *OAuth2Client) Client(ctx context.Context, token *Token) *http.Client {
	return &http.Client{
		Transport: &oauth2Transport{
			base:   c.HTTPClient.Transport,
			token:  token,
			client: c,
		},
	}
}

// oauth2Transport OAuth2传输层
type oauth2Transport struct {
	base   http.RoundTripper
	token  *Token
	client *OAuth2Client
}

// RoundTrip 实现http.RoundTripper接口
func (t *oauth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token == nil {
		return t.base.RoundTrip(req)
	}

	req2 := cloneRequest(req)
	req2.Header.Set("Authorization", "Bearer "+t.token.AccessToken)
	return t.base.RoundTrip(req2)
}

// cloneRequest 克隆请求
func cloneRequest(r *http.Request) *http.Request {
	r2 := new(http.Request)
	*r2 = *r
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
