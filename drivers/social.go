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
)

// 社交登录提供商类型常量
const (
	ProviderGitHub = "github"
	ProviderGoogle = "google"
	ProviderWeChat = "wechat"
)

// SocialUser 表示从社交平台获取的用户信息
type SocialUser struct {
	ID       string
	Name     string
	Email    string
	Avatar   string
	Provider string
	RawData  map[string]interface{}
}

// UserRepository 定义了查找和创建用户的接口
type UserRepository interface {
	// FindUserBySocialID 通过社交ID查找用户
	FindUserBySocialID(ctx context.Context, provider, socialID string) (interface{}, error)
	// CreateUser 创建新用户
	CreateUser(ctx context.Context, user interface{}) error
}

// CreateUserCallback 是创建用户的回调函数类型
type CreateUserCallback func(ctx context.Context, user *SocialUser) (interface{}, error)

// Token 表示OAuth2认证令牌
type Token struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiry       time.Time
	Raw          map[string]interface{}
}

// SocialProvider 定义了社交登录提供商接口
type SocialProvider interface {
	// GetName 返回提供商名称
	GetName() string
	// GetAuthURL 返回授权URL
	GetAuthURL(state string) string
	// ExchangeToken 使用授权码交换访问令牌
	ExchangeToken(ctx context.Context, code string) (*Token, error)
	// GetUserInfo 通过访问令牌获取用户信息
	GetUserInfo(ctx context.Context, token *Token) (*SocialUser, error)
}

// SocialManager 管理社交登录
type SocialManager struct {
	// 提供商映射
	providers map[string]SocialProvider
	// 用户仓库
	userRepo UserRepository
	// 用户创建回调
	createCallback CreateUserCallback
}

// NewSocialManager 创建新的社交登录管理器
func NewSocialManager(userRepo UserRepository) *SocialManager {
	return &SocialManager{
		providers: make(map[string]SocialProvider),
		userRepo:  userRepo,
		createCallback: func(ctx context.Context, user *SocialUser) (interface{}, error) {
			return user, nil
		},
	}
}

// RegisterProvider 注册社交登录提供商
func (m *SocialManager) RegisterProvider(provider SocialProvider) {
	m.providers[provider.GetName()] = provider
}

// SetCreateUserCallback 设置创建用户的回调函数
func (m *SocialManager) SetCreateUserCallback(callback CreateUserCallback) {
	m.createCallback = callback
}

// HandleLogin 处理登录请求
func (m *SocialManager) HandleLogin(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider, ok := m.providers[providerName]
		if !ok {
			http.Error(w, "不支持的登录提供商", http.StatusBadRequest)
			return
		}

		// 生成状态值（在实际应用中应该使用随机字符串并存储在会话中）
		state := "state"

		// 重定向到授权URL
		authURL := provider.GetAuthURL(state)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// HandleCallback 处理回调请求
func (m *SocialManager) HandleCallback(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 获取查询参数
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		// 在实际应用中应该验证状态值
		_ = state

		// 获取提供商
		provider, ok := m.providers[providerName]
		if !ok {
			http.Error(w, "不支持的登录提供商", http.StatusBadRequest)
			return
		}

		// 使用授权码交换访问令牌
		token, err := provider.ExchangeToken(r.Context(), code)
		if err != nil {
			http.Error(w, "无法交换令牌: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 获取用户信息
		socialUser, err := provider.GetUserInfo(r.Context(), token)
		if err != nil {
			http.Error(w, "无法获取用户信息: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 查找现有用户
		user, err := m.userRepo.FindUserBySocialID(r.Context(), providerName, socialUser.ID)
		if err != nil {
			http.Error(w, "查找用户时出错: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 如果用户不存在，创建新用户
		if user == nil {
			newUser, err := m.createCallback(r.Context(), socialUser)
			if err != nil {
				http.Error(w, "创建用户时出错: "+err.Error(), http.StatusInternalServerError)
				return
			}

			err = m.userRepo.CreateUser(r.Context(), newUser)
			if err != nil {
				http.Error(w, "保存用户时出错: "+err.Error(), http.StatusInternalServerError)
				return
			}

			user = newUser
		}

		// 将用户信息存储在会话中
		// 注意：这是示例代码，实际应用中应该使用会话管理或JWT等认证机制
		// sess.Set("user", user)

		// 重定向到用户页面
		http.Redirect(w, r, "/user", http.StatusFound)
	}
}

// BaseSocialProvider 是社交登录提供商的基础实现
type BaseSocialProvider struct {
	name         string
	clientID     string
	clientSecret string
	redirectURL  string
	authURL      string
	tokenURL     string
	userInfoURL  string
	scopes       []string
}

// GetName 返回提供商名称
func (p *BaseSocialProvider) GetName() string {
	return p.name
}

// GetAuthURL 返回授权URL
func (p *BaseSocialProvider) GetAuthURL(state string) string {
	u, _ := url.Parse(p.authURL)
	q := u.Query()

	q.Set("client_id", p.clientID)
	q.Set("redirect_uri", p.redirectURL)
	q.Set("response_type", "code")
	q.Set("state", state)

	if len(p.scopes) > 0 {
		q.Set("scope", strings.Join(p.scopes, " "))
	}

	u.RawQuery = q.Encode()
	return u.String()
}

// ExchangeToken 使用授权码交换访问令牌
func (p *BaseSocialProvider) ExchangeToken(ctx context.Context, code string) (*Token, error) {
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", p.redirectURL)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取令牌失败: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	// 检查错误
	if errMsg, ok := result["error"]; ok {
		return nil, fmt.Errorf("OAuth错误: %v", errMsg)
	}

	// 构建令牌
	token := &Token{
		Raw: result,
	}

	if access, ok := result["access_token"].(string); ok {
		token.AccessToken = access
	} else {
		return nil, errors.New("缺少访问令牌")
	}

	if tokenType, ok := result["token_type"].(string); ok {
		token.TokenType = tokenType
	}

	if refresh, ok := result["refresh_token"].(string); ok {
		token.RefreshToken = refresh
	}

	if expiresIn, ok := result["expires_in"].(float64); ok {
		token.Expiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}

	return token, nil
}

// GitHubProvider 实现GitHub登录
type GitHubProvider struct {
	BaseSocialProvider
}

// NewGitHubProvider 创建新的GitHub登录提供商
func NewGitHubProvider(config map[string]interface{}) *GitHubProvider {
	clientID, _ := config["client_id"].(string)
	clientSecret, _ := config["client_secret"].(string)
	redirectURL, _ := config["redirect_url"].(string)

	var scopes []string
	if scopesAny, ok := config["scopes"].([]string); ok {
		scopes = scopesAny
	} else if scopesAny, ok := config["scopes"].([]interface{}); ok {
		for _, s := range scopesAny {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}

	return &GitHubProvider{
		BaseSocialProvider: BaseSocialProvider{
			name:         ProviderGitHub,
			clientID:     clientID,
			clientSecret: clientSecret,
			redirectURL:  redirectURL,
			authURL:      "https://github.com/login/oauth/authorize",
			tokenURL:     "https://github.com/login/oauth/access_token",
			userInfoURL:  "https://api.github.com/user",
			scopes:       scopes,
		},
	}
}

// GetUserInfo 从GitHub获取用户信息
func (p *GitHubProvider) GetUserInfo(ctx context.Context, token *Token) (*SocialUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.userInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取用户信息失败: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userData map[string]interface{}
	if err := json.Unmarshal(body, &userData); err != nil {
		return nil, err
	}

	// 提取用户信息
	user := &SocialUser{
		Provider: p.name,
		RawData:  userData,
	}

	if id, ok := userData["id"]; ok {
		user.ID = fmt.Sprintf("%v", id)
	}

	if name, ok := userData["name"].(string); ok {
		user.Name = name
	} else if login, ok := userData["login"].(string); ok {
		user.Name = login
	}

	if email, ok := userData["email"].(string); ok {
		user.Email = email
	}

	if avatar, ok := userData["avatar_url"].(string); ok {
		user.Avatar = avatar
	}

	// 如果没有获取到邮箱且有适当的权限，获取用户邮箱
	if user.Email == "" && p.hasScope("user:email") {
		email := p.getGitHubEmail(ctx, token.AccessToken)
		if email != "" {
			user.Email = email
		}
	}

	return user, nil
}

// hasScope 检查是否有特定权限
func (p *GitHubProvider) hasScope(scope string) bool {
	for _, s := range p.scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// getGitHubEmail 获取GitHub用户邮箱
func (p *GitHubProvider) getGitHubEmail(ctx context.Context, accessToken string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return ""
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var emails []map[string]interface{}
	if err := json.Unmarshal(body, &emails); err != nil {
		return ""
	}

	// 查找主邮箱
	for _, email := range emails {
		primary, _ := email["primary"].(bool)
		verified, _ := email["verified"].(bool)
		if primary && verified {
			if emailStr, ok := email["email"].(string); ok {
				return emailStr
			}
		}
	}

	return ""
}

// GoogleProvider 实现Google登录
type GoogleProvider struct {
	BaseSocialProvider
}

// NewGoogleProvider 创建新的Google登录提供商
func NewGoogleProvider(config map[string]interface{}) *GoogleProvider {
	clientID, _ := config["client_id"].(string)
	clientSecret, _ := config["client_secret"].(string)
	redirectURL, _ := config["redirect_url"].(string)

	var scopes []string
	if scopesAny, ok := config["scopes"].([]string); ok {
		scopes = scopesAny
	} else if scopesAny, ok := config["scopes"].([]interface{}); ok {
		for _, s := range scopesAny {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}

	if len(scopes) == 0 {
		scopes = []string{"profile", "email"}
	}

	return &GoogleProvider{
		BaseSocialProvider: BaseSocialProvider{
			name:         ProviderGoogle,
			clientID:     clientID,
			clientSecret: clientSecret,
			redirectURL:  redirectURL,
			authURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			tokenURL:     "https://oauth2.googleapis.com/token",
			userInfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
			scopes:       scopes,
		},
	}
}

// GetUserInfo 从Google获取用户信息
func (p *GoogleProvider) GetUserInfo(ctx context.Context, token *Token) (*SocialUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.userInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取用户信息失败: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userData map[string]interface{}
	if err := json.Unmarshal(body, &userData); err != nil {
		return nil, err
	}

	// 提取用户信息
	user := &SocialUser{
		Provider: p.name,
		RawData:  userData,
	}

	if id, ok := userData["sub"].(string); ok {
		user.ID = id
	}

	if name, ok := userData["name"].(string); ok {
		user.Name = name
	}

	if email, ok := userData["email"].(string); ok {
		user.Email = email
	}

	if picture, ok := userData["picture"].(string); ok {
		user.Avatar = picture
	}

	return user, nil
}

// WeChatProvider 实现微信登录
type WeChatProvider struct {
	BaseSocialProvider
}

// NewWeChatProvider 创建新的微信登录提供商
func NewWeChatProvider(config map[string]interface{}) *WeChatProvider {
	clientID, _ := config["client_id"].(string)
	clientSecret, _ := config["client_secret"].(string)
	redirectURL, _ := config["redirect_url"].(string)

	var scopes []string
	if scopesAny, ok := config["scopes"].([]string); ok {
		scopes = scopesAny
	} else if scopesAny, ok := config["scopes"].([]interface{}); ok {
		for _, s := range scopesAny {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}

	if len(scopes) == 0 {
		scopes = []string{"snsapi_login"}
	}

	return &WeChatProvider{
		BaseSocialProvider: BaseSocialProvider{
			name:         ProviderWeChat,
			clientID:     clientID,
			clientSecret: clientSecret,
			redirectURL:  redirectURL,
			authURL:      "https://open.weixin.qq.com/connect/qrconnect",
			tokenURL:     "https://api.weixin.qq.com/sns/oauth2/access_token",
			userInfoURL:  "https://api.weixin.qq.com/sns/userinfo",
			scopes:       scopes,
		},
	}
}

// GetAuthURL 返回微信授权URL
func (p *WeChatProvider) GetAuthURL(state string) string {
	// 微信的OAuth实现有点特殊
	u, _ := url.Parse(p.authURL)
	q := u.Query()

	q.Set("appid", p.clientID)
	q.Set("redirect_uri", p.redirectURL)
	q.Set("response_type", "code")
	q.Set("state", state)

	if len(p.scopes) > 0 {
		q.Set("scope", strings.Join(p.scopes, ","))
	}

	u.RawQuery = q.Encode()
	return u.String() + "#wechat_redirect"
}

// ExchangeToken 交换微信访问令牌
func (p *WeChatProvider) ExchangeToken(ctx context.Context, code string) (*Token, error) {
	// 微信的令牌交换与标准OAuth不同
	u, _ := url.Parse(p.tokenURL)
	q := u.Query()

	q.Set("appid", p.clientID)
	q.Set("secret", p.clientSecret)
	q.Set("code", code)
	q.Set("grant_type", "authorization_code")

	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	// 检查错误
	if errcode, ok := result["errcode"].(float64); ok && errcode != 0 {
		return nil, fmt.Errorf("微信API错误: %v", result["errmsg"])
	}

	// 构建令牌
	token := &Token{
		Raw: result,
	}

	if access, ok := result["access_token"].(string); ok {
		token.AccessToken = access
	} else {
		return nil, errors.New("缺少访问令牌")
	}

	if refresh, ok := result["refresh_token"].(string); ok {
		token.RefreshToken = refresh
	}

	if expiresIn, ok := result["expires_in"].(float64); ok {
		token.Expiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}

	// 添加openid到令牌中
	if openid, ok := result["openid"].(string); ok {
		if token.Raw == nil {
			token.Raw = make(map[string]interface{})
		}
		token.Raw["openid"] = openid
	} else {
		return nil, errors.New("缺少openid")
	}

	return token, nil
}

// GetUserInfo 获取微信用户信息
func (p *WeChatProvider) GetUserInfo(ctx context.Context, token *Token) (*SocialUser, error) {
	openid, ok := token.Raw["openid"].(string)
	if !ok {
		return nil, errors.New("缺少openid")
	}

	// 构建URL
	u, _ := url.Parse(p.userInfoURL)
	q := u.Query()

	q.Set("access_token", token.AccessToken)
	q.Set("openid", openid)
	q.Set("lang", "zh_CN")

	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userData map[string]interface{}
	if err := json.Unmarshal(body, &userData); err != nil {
		return nil, err
	}

	// 检查错误
	if errcode, ok := userData["errcode"].(float64); ok && errcode != 0 {
		return nil, fmt.Errorf("微信API错误: %v", userData["errmsg"])
	}

	// 提取用户信息
	user := &SocialUser{
		Provider: p.name,
		RawData:  userData,
	}

	user.ID = openid

	if nickname, ok := userData["nickname"].(string); ok {
		user.Name = nickname
	}

	if headimgurl, ok := userData["headimgurl"].(string); ok {
		user.Avatar = headimgurl
	}

	// 微信不提供邮箱
	user.Email = ""

	return user, nil
}
