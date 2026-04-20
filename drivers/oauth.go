package drivers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/zzliekkas/flow-auth/v3"
	"github.com/zzliekkas/flow/v3"
)

// OAuth2Config OAuth2配置
type OAuth2Config struct {
	// ClientID 客户端ID
	ClientID string

	// ClientSecret 客户端密钥
	ClientSecret string

	// RedirectURI 重定向URI
	RedirectURI string

	// AuthURL 授权URL
	AuthURL string

	// TokenURL 令牌URL
	TokenURL string

	// UserInfoURL 用户信息URL
	UserInfoURL string

	// Scopes 请求的作用域
	Scopes []string

	// ResponseType 响应类型，默认为"code"
	ResponseType string

	// StateParam 状态参数，用于防止CSRF攻击
	StateParam string
}

// OAuth2Token OAuth2令牌
type OAuth2Token struct {
	// AccessToken 访问令牌
	AccessToken string `json:"access_token"`

	// RefreshToken 刷新令牌
	RefreshToken string `json:"refresh_token"`

	// TokenType 令牌类型
	TokenType string `json:"token_type"`

	// ExpiresIn 过期时间（秒）
	ExpiresIn int64 `json:"expires_in"`

	// CreatedAt 创建时间
	CreatedAt time.Time `json:"-"`
}

// IsExpired 检查令牌是否已过期
func (t *OAuth2Token) IsExpired() bool {
	return time.Now().After(t.CreatedAt.Add(time.Duration(t.ExpiresIn) * time.Second))
}

// OAuth2Provider OAuth2认证提供者
type OAuth2Provider struct {
	// 用户提供者
	userProvider auth.UserProvider

	// 配置
	config OAuth2Config

	// 令牌存储
	tokenStorage map[string]*OAuth2Token
}

// NewOAuth2Provider 创建新的OAuth2认证提供者
func NewOAuth2Provider(userProvider auth.UserProvider, config OAuth2Config) *OAuth2Provider {
	if config.ResponseType == "" {
		config.ResponseType = "code"
	}

	return &OAuth2Provider{
		userProvider: userProvider,
		config:       config,
		tokenStorage: make(map[string]*OAuth2Token),
	}
}

// GetAuthURL 获取授权URL
func (p *OAuth2Provider) GetAuthURL(state string) string {
	params := url.Values{}
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", p.config.RedirectURI)
	params.Set("response_type", p.config.ResponseType)
	params.Set("state", state)

	if len(p.config.Scopes) > 0 {
		params.Set("scope", strings.Join(p.config.Scopes, " "))
	}

	return fmt.Sprintf("%s?%s", p.config.AuthURL, params.Encode())
}

// ExchangeCode 通过授权码交换访问令牌
func (p *OAuth2Provider) ExchangeCode(code string) (*OAuth2Token, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	data.Set("redirect_uri", p.config.RedirectURI)

	req, err := http.NewRequest("POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OAuth2 token exchange failed: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var token OAuth2Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	token.CreatedAt = time.Now()
	return &token, nil
}

// GetUserInfo 获取用户信息
func (p *OAuth2Provider) GetUserInfo(token *OAuth2Token) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))
	req.Header.Add("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to get user info: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}

// Authenticate 验证用户凭证并返回已认证用户
func (p *OAuth2Provider) Authenticate(ctx context.Context, credentials map[string]string) (auth.Authenticatable, error) {
	// OAuth2不支持直接使用凭证认证，应该使用授权码流程
	return nil, errors.New("OAuth2 不支持直接凭证认证，请使用授权码流程")
}

// AuthenticateWithCode 使用授权码认证
func (p *OAuth2Provider) AuthenticateWithCode(ctx context.Context, code string) (auth.Authenticatable, string, error) {
	// 交换授权码获取访问令牌
	token, err := p.ExchangeCode(code)
	if err != nil {
		return nil, "", err
	}

	// 获取用户信息
	userInfo, err := p.GetUserInfo(token)
	if err != nil {
		return nil, "", err
	}

	// 检查是否有用户ID
	userIDField := "id"
	// 用户名字段，可能会在用户创建时使用
	// userNameField := "name"

	userID, ok := userInfo[userIDField].(string)
	if !ok {
		// 尝试其他可能的字段
		userIDField = "sub"
		userID, ok = userInfo[userIDField].(string)
		if !ok {
			return nil, "", fmt.Errorf("用户信息中找不到有效的用户ID字段")
		}
	}

	// 尝试通过ID找用户
	user, err := p.userProvider.FindByID(ctx, userID)
	if err != nil && err != auth.ErrUserNotFound {
		return nil, "", err
	}

	if user == nil {
		// 用户不存在，需要创建
		// 注意：这里需要应用程序提供特定的实现
		return nil, "", fmt.Errorf("用户不存在，需要应用程序处理用户创建")
	}

	// 存储令牌用于后续使用
	userIDStr := user.GetAuthIdentifier()
	p.tokenStorage[userIDStr] = token

	// 返回用户和令牌
	return user, token.AccessToken, nil
}

// GetUserByID 通过ID获取用户
func (p *OAuth2Provider) GetUserByID(ctx context.Context, id string) (auth.Authenticatable, error) {
	return p.userProvider.FindByID(ctx, id)
}

// GenerateToken 为用户生成认证令牌
func (p *OAuth2Provider) GenerateToken(ctx context.Context, user auth.Authenticatable, expiry time.Duration) (string, error) {
	// 检查是否已有令牌
	userID := user.GetAuthIdentifier()
	if token, ok := p.tokenStorage[userID]; ok && !token.IsExpired() {
		return token.AccessToken, nil
	}

	// OAuth2模式下，我们不能直接生成令牌，需要走授权流程
	return "", errors.New("OAuth2模式下不支持直接生成令牌，请使用授权流程")
}

// ValidateToken 验证令牌并返回关联的用户
func (p *OAuth2Provider) ValidateToken(ctx context.Context, tokenString string) (auth.Authenticatable, error) {
	// 在令牌存储中查找对应的用户
	for userID, token := range p.tokenStorage {
		if token.AccessToken == tokenString {
			if token.IsExpired() {
				// 令牌已过期
				delete(p.tokenStorage, userID)
				return nil, auth.ErrInvalidToken
			}

			// 返回用户
			return p.userProvider.FindByID(ctx, userID)
		}
	}

	return nil, auth.ErrInvalidToken
}

// RefreshToken 刷新认证令牌
func (p *OAuth2Provider) RefreshToken(ctx context.Context, tokenString string) (string, error) {
	// 查找原始令牌
	var userID string
	var oldToken *OAuth2Token

	for id, token := range p.tokenStorage {
		if token.AccessToken == tokenString {
			userID = id
			oldToken = token
			break
		}
	}

	if oldToken == nil || oldToken.RefreshToken == "" {
		return "", auth.ErrInvalidToken
	}

	// 使用刷新令牌获取新令牌
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", oldToken.RefreshToken)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)

	req, err := http.NewRequest("POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("刷新令牌失败: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var newToken OAuth2Token
	if err := json.Unmarshal(body, &newToken); err != nil {
		return "", err
	}

	newToken.CreatedAt = time.Now()

	// 更新令牌存储
	p.tokenStorage[userID] = &newToken

	return newToken.AccessToken, nil
}

// InvalidateToken 使令牌失效
func (p *OAuth2Provider) InvalidateToken(ctx context.Context, tokenString string) error {
	// 查找并删除令牌
	for userID, token := range p.tokenStorage {
		if token.AccessToken == tokenString {
			delete(p.tokenStorage, userID)
			return nil
		}
	}

	return auth.ErrInvalidToken
}

// CheckPermission 检查用户是否拥有指定权限
func (p *OAuth2Provider) CheckPermission(ctx context.Context, user auth.Authenticatable, permission string) bool {
	permissions := user.GetPermissions()
	for _, userPerm := range permissions {
		if userPerm == permission || userPerm == "*" {
			return true
		}
	}
	return false
}

// CheckRole 检查用户是否拥有指定角色
func (p *OAuth2Provider) CheckRole(ctx context.Context, user auth.Authenticatable, role string) bool {
	roles := user.GetRoles()
	for _, userRole := range roles {
		if userRole == role {
			return true
		}
	}
	return false
}

// HandleCallback 处理OAuth2回调
func (p *OAuth2Provider) HandleCallback() flow.HandlerFunc {
	return func(c *flow.Context) {
		// 获取授权码
		code := c.Query("code")
		if code == "" {
			c.JSON(http.StatusBadRequest, flow.H{
				"error": "缺少授权码",
			})
			return
		}

		// 获取状态参数并验证
		state := c.Query("state")
		if state == "" || state != p.config.StateParam {
			c.JSON(http.StatusBadRequest, flow.H{
				"error": "无效的状态参数",
			})
			return
		}

		// 使用授权码认证
		user, token, err := p.AuthenticateWithCode(c.Request.Context(), code)
		if err != nil {
			c.JSON(http.StatusUnauthorized, flow.H{
				"error": err.Error(),
			})
			return
		}

		// 将用户和令牌添加到上下文
		ctx := auth.WithUser(c.Request.Context(), user)
		ctx = auth.WithToken(ctx, token)
		c.Request = c.Request.WithContext(ctx)

		// 将用户添加到Flow上下文
		c.Set("auth_user", user)

		// 重定向到首页或其他指定页面
		redirectURL := c.Query("redirect_uri")
		if redirectURL == "" {
			redirectURL = "/"
		}

		c.Redirect(http.StatusFound, redirectURL)
	}
}
