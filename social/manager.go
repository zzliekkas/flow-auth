package social

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/zzliekkas/flow/v2"
	"github.com/zzliekkas/flow-auth/oauth"
)

// Provider 社交登录提供者接口
type Provider interface {
	// Name 提供者名称
	Name() string

	// GetOAuth2Config 获取OAuth2配置
	GetOAuth2Config() oauth.OAuth2Config

	// GetUserInfo 获取用户信息
	GetUserInfo(ctx context.Context, token *oauth.Token) (*UserInfo, error)
}

// UserInfo 用户信息
type UserInfo struct {
	// 提供者名称
	Provider string `json:"provider"`

	// 提供者用户ID
	ProviderUserID string `json:"provider_user_id"`

	// 用户名
	Username string `json:"username"`

	// 昵称
	Nickname string `json:"nickname"`

	// 邮箱
	Email string `json:"email"`

	// 头像URL
	Avatar string `json:"avatar"`

	// 原始数据
	Raw map[string]interface{} `json:"raw"`
}

// Manager 社交登录管理器
type Manager struct {
	// 提供者映射
	providers map[string]Provider

	// 配置
	config *Config

	// 互斥锁
	mu sync.RWMutex
}

// Config 社交登录配置
type Config struct {
	// 登录成功回调URL
	SuccessURL string

	// 登录失败回调URL
	FailureURL string

	// 状态验证密钥
	StateSecret string

	// Session存储
	SessionStore interface{}

	// 用户映射器
	UserMapper UserMapper
}

// NewManager 创建社交登录管理器
func NewManager(config *Config) *Manager {
	if config == nil {
		config = &Config{}
	}

	return &Manager{
		providers: make(map[string]Provider),
		config:    config,
	}
}

// RegisterProvider 注册提供者
func (m *Manager) RegisterProvider(provider Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.providers[provider.Name()] = provider
}

// GetProvider 获取提供者
func (m *Manager) GetProvider(name string) (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, ok := m.providers[name]
	if !ok {
		return nil, fmt.Errorf("未找到提供者: %s", name)
	}

	return provider, nil
}

// HandleLogin 处理登录请求
func (m *Manager) HandleLogin(ctx *flow.Context) {
	providerName := ctx.Param("provider")
	provider, err := m.GetProvider(providerName)
	if err != nil {
		ctx.String(http.StatusBadRequest, err.Error())
		return
	}

	// 生成并保存state
	state := generateState()
	if err := m.saveState(ctx, state); err != nil {
		ctx.String(http.StatusInternalServerError, "保存状态失败")
		return
	}

	// 生成授权URL
	authURL := provider.GetOAuth2Config().AuthCodeURL(state)
	ctx.Redirect(http.StatusTemporaryRedirect, authURL)
}

// HandleCallback 处理回调请求
func (m *Manager) HandleCallback(ctx *flow.Context) {
	providerName := ctx.Param("provider")
	provider, err := m.GetProvider(providerName)
	if err != nil {
		ctx.String(http.StatusBadRequest, err.Error())
		return
	}

	// 验证state
	state := ctx.Query("state")
	if err := m.validateState(ctx, state); err != nil {
		ctx.String(http.StatusBadRequest, "无效的状态")
		return
	}

	// 获取授权码
	code := ctx.Query("code")
	if code == "" {
		ctx.String(http.StatusBadRequest, "未提供授权码")
		return
	}

	// 交换访问令牌
	token, err := provider.GetOAuth2Config().Exchange(ctx.Request.Context(), code)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "获取访问令牌失败")
		return
	}

	// 获取用户信息
	userInfo, err := provider.GetUserInfo(ctx.Request.Context(), token)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "获取用户信息失败")
		return
	}

	// 映射用户
	if m.config.UserMapper != nil {
		if err := m.config.UserMapper.MapUser(ctx, userInfo); err != nil {
			ctx.String(http.StatusInternalServerError, "用户映射失败")
			return
		}
	}

	// 重定向到成功URL
	successURL := m.config.SuccessURL
	if successURL == "" {
		successURL = "/"
	}
	ctx.Redirect(http.StatusTemporaryRedirect, successURL)
}

// generateState 生成状态值
func generateState() string {
	// 实现状态生成逻辑
	return "" // TODO: 实现
}

// saveState 保存状态
func (m *Manager) saveState(ctx *flow.Context, state string) error {
	// 实现状态保存逻辑
	return nil // TODO: 实现
}

// validateState 验证状态
func (m *Manager) validateState(ctx *flow.Context, state string) error {
	if state == "" {
		return errors.New("状态为空")
	}
	// 实现状态验证逻辑
	return nil // TODO: 实现
}

// RegisterHandlers 注册路由处理器
func (m *Manager) RegisterHandlers(e *flow.Engine) {
	group := e.Group("/auth")
	{
		group.GET("/:provider", m.HandleLogin)
		group.GET("/:provider/callback", m.HandleCallback)
	}
}
