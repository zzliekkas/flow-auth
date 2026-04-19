package auth

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/zzliekkas/flow/v3"
)

// 添加缺失的错误常量
var (
	// ErrPermissionDenied 表示用户没有足够的权限访问资源
	ErrPermissionDenied = errors.New("权限不足")
)

// Manager 是认证管理器，负责协调多个认证提供者
type Manager struct {
	// 默认认证提供者名称
	defaultProvider string

	// 注册的认证提供者映射
	providers map[string]AuthProvider

	// 配置
	config *Config

	// 互斥锁，用于并发访问
	mu sync.RWMutex
}

// Config 是认证系统的配置
type Config struct {
	// DefaultProvider 默认认证提供者名称
	DefaultProvider string

	// TokenExpiry 令牌默认过期时间
	TokenExpiry time.Duration

	// ContextKey 存储在Flow上下文中的已认证用户键名
	ContextKey string

	// LoginURL 登录页面URL
	LoginURL string

	// LogoutURL 登出页面URL
	LogoutURL string

	// RedirectKey 重定向URL参数键名
	RedirectKey string

	// CookieName 认证Cookie名称
	CookieName string

	// CookiePath Cookie路径
	CookiePath string

	// CookieDomain Cookie域
	CookieDomain string

	// CookieSecure Cookie是否仅通过HTTPS发送
	CookieSecure bool

	// CookieHTTPOnly Cookie是否仅可通过HTTP访问
	CookieHTTPOnly bool

	// SessionDriver 会话驱动类型
	SessionDriver string

	// UserProvider 用户提供者实现
	UserProvider UserProvider
}

// UserProvider 是用户数据提供者接口
// type UserProvider interface {
// 	// FindByID 根据ID查找用户
// 	FindByID(ctx context.Context, id string) (Authenticatable, error)
//
// 	// FindByCredentials 根据凭证查找用户
// 	FindByCredentials(ctx context.Context, credentials map[string]string) (Authenticatable, error)
//
// 	// ValidateCredentials 验证用户凭证
// 	ValidateCredentials(ctx context.Context, user Authenticatable, credentials map[string]string) (bool, error)
// }

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		DefaultProvider: "jwt",
		TokenExpiry:     time.Hour * 24,
		ContextKey:      "auth_user",
		LoginURL:        "/login",
		LogoutURL:       "/logout",
		RedirectKey:     "redirect",
		CookieName:      "auth_token",
		CookiePath:      "/",
		CookieHTTPOnly:  true,
		SessionDriver:   "cookie",
	}
}

// NewManager 创建新的认证管理器
func NewManager(config *Config) *Manager {
	if config == nil {
		config = DefaultConfig()
	}

	return &Manager{
		defaultProvider: config.DefaultProvider,
		providers:       make(map[string]AuthProvider),
		config:          config,
	}
}

// RegisterProvider 注册认证提供者
func (m *Manager) RegisterProvider(name string, provider AuthProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.providers[name] = provider
}

// Provider 获取指定名称的认证提供者
func (m *Manager) Provider(name string) (AuthProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if provider, exists := m.providers[name]; exists {
		return provider, nil
	}

	return nil, errors.New("未找到认证提供者: " + name)
}

// DefaultProvider 获取默认认证提供者
func (m *Manager) DefaultProvider() (AuthProvider, error) {
	return m.Provider(m.defaultProvider)
}

// SetDefaultProvider 设置默认认证提供者
func (m *Manager) SetDefaultProvider(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.defaultProvider = name
}

// Authenticate 使用默认提供者进行认证
func (m *Manager) Authenticate(ctx context.Context, credentials map[string]string) (Authenticatable, error) {
	provider, err := m.DefaultProvider()
	if err != nil {
		return nil, err
	}

	return provider.Authenticate(ctx, credentials)
}

// GetUserByID 使用默认提供者根据ID获取用户
func (m *Manager) GetUserByID(ctx context.Context, id string) (Authenticatable, error) {
	provider, err := m.DefaultProvider()
	if err != nil {
		return nil, err
	}

	return provider.GetUserByID(ctx, id)
}

// GenerateToken 使用默认提供者为用户生成令牌
func (m *Manager) GenerateToken(ctx context.Context, user Authenticatable) (string, error) {
	provider, err := m.DefaultProvider()
	if err != nil {
		return "", err
	}

	return provider.GenerateToken(ctx, user, m.config.TokenExpiry)
}

// ValidateToken 使用默认提供者验证令牌
func (m *Manager) ValidateToken(ctx context.Context, token string) (Authenticatable, error) {
	provider, err := m.DefaultProvider()
	if err != nil {
		return nil, err
	}

	return provider.ValidateToken(ctx, token)
}

// RefreshToken 使用默认提供者刷新令牌
func (m *Manager) RefreshToken(ctx context.Context, token string) (string, error) {
	provider, err := m.DefaultProvider()
	if err != nil {
		return "", err
	}

	return provider.RefreshToken(ctx, token)
}

// InvalidateToken 使用默认提供者使令牌失效
func (m *Manager) InvalidateToken(ctx context.Context, token string) error {
	provider, err := m.DefaultProvider()
	if err != nil {
		return err
	}

	return provider.InvalidateToken(ctx, token)
}

// Check 检查用户是否拥有指定权限
func (m *Manager) Check(ctx context.Context, user Authenticatable, permission string) bool {
	provider, err := m.DefaultProvider()
	if err != nil {
		return false
	}

	return provider.CheckPermission(ctx, user, permission)
}

// HasRole 检查用户是否拥有指定角色
func (m *Manager) HasRole(ctx context.Context, user Authenticatable, role string) bool {
	provider, err := m.DefaultProvider()
	if err != nil {
		return false
	}

	return provider.CheckRole(ctx, user, role)
}

// AuthMiddleware 创建认证中间件
func (m *Manager) AuthMiddleware() flow.HandlerFunc {
	return func(c *flow.Context) {
		// 从请求中提取令牌
		token := extractTokenFromRequest(c, m.config)
		if token == "" {
			c.Next()
			return
		}

		// 验证令牌并获取用户
		user, err := m.ValidateToken(c.Request.Context(), token)
		if err != nil {
			c.Next()
			return
		}

		// 将用户和令牌添加到上下文
		ctx := WithUser(c.Request.Context(), user)
		ctx = WithToken(ctx, token)
		c.Request = c.Request.WithContext(ctx)

		// 将用户添加到Flow上下文
		c.Set(m.config.ContextKey, user)

		c.Next()
	}
}

// RequireAuth 创建要求认证的中间件
func (m *Manager) RequireAuth() flow.HandlerFunc {
	return func(c *flow.Context) {
		// 从请求中提取令牌
		token := extractTokenFromRequest(c, m.config)
		if token == "" {
			// 重定向到登录页面
			redirectToLogin(c, m.config)
			return
		}

		// 验证令牌并获取用户
		user, err := m.ValidateToken(c.Request.Context(), token)
		if err != nil {
			// 重定向到登录页面
			redirectToLogin(c, m.config)
			return
		}

		// 将用户和令牌添加到上下文
		ctx := WithUser(c.Request.Context(), user)
		ctx = WithToken(ctx, token)
		c.Request = c.Request.WithContext(ctx)

		// 将用户添加到Flow上下文
		c.Set(m.config.ContextKey, user)

		c.Next()
	}
}

// RequirePermission 创建要求特定权限的中间件
func (m *Manager) RequirePermission(permission string) flow.HandlerFunc {
	return func(c *flow.Context) {
		// 先确保用户已认证
		user, exists := UserFromContext(c.Request.Context())
		if !exists {
			// 重定向到登录页面
			redirectToLogin(c, m.config)
			return
		}

		// 检查用户是否拥有权限
		if !m.Check(c.Request.Context(), user, permission) {
			// 权限被拒绝
			c.JSON(403, flow.H{
				"error": ErrPermissionDenied.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole 创建要求特定角色的中间件
func (m *Manager) RequireRole(role string) flow.HandlerFunc {
	return func(c *flow.Context) {
		// 先确保用户已认证
		user, exists := UserFromContext(c.Request.Context())
		if !exists {
			// 重定向到登录页面
			redirectToLogin(c, m.config)
			return
		}

		// 检查用户是否拥有角色
		if !m.HasRole(c.Request.Context(), user, role) {
			// 权限被拒绝
			c.JSON(403, flow.H{
				"error": ErrPermissionDenied.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetUser 从Flow上下文中获取已认证用户
func (m *Manager) GetUser(c *flow.Context) (Authenticatable, bool) {
	// 首先尝试从请求上下文获取
	if user, exists := UserFromContext(c.Request.Context()); exists {
		return user, true
	}

	// 然后尝试从Flow上下文获取
	if user, exists := c.Get(m.config.ContextKey); exists {
		if authUser, ok := user.(Authenticatable); ok {
			return authUser, true
		}
	}

	// 最后尝试从令牌中获取
	token := extractTokenFromRequest(c, m.config)
	if token != "" {
		if user, err := m.ValidateToken(c.Request.Context(), token); err == nil {
			return user, true
		}
	}

	return nil, false
}

// extractTokenFromRequest 从请求中提取认证令牌
func extractTokenFromRequest(c *flow.Context, config *Config) string {
	// 尝试从请求头中提取
	token := c.Request.Header.Get("Authorization")
	if token != "" {
		// 移除Bearer前缀
		if len(token) > 7 && token[:7] == "Bearer " {
			return token[7:]
		}
		return token
	}

	// 尝试从查询参数中提取
	token = c.Query("token")
	if token != "" {
		return token
	}

	// 尝试从Cookie中提取
	cookie, err := c.Cookie(config.CookieName)
	if err == nil {
		return cookie
	}

	return ""
}

// redirectToLogin 重定向到登录页面
func redirectToLogin(c *flow.Context, config *Config) {
	// 保存当前URL用于登录后重定向
	redirectURL := c.Request.URL.String()
	loginURL := config.LoginURL

	// 如果是AJAX请求，返回401状态码
	if c.Request.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		c.JSON(401, flow.H{
			"error":  "认证失败",
			"login":  loginURL,
			"status": 401,
		})
		c.Abort()
		return
	}

	// 添加重定向参数（URL编码防止特殊字符破坏URL）
	if redirectURL != "" && redirectURL != config.LoginURL {
		loginURL += "?" + config.RedirectKey + "=" + url.QueryEscape(redirectURL)
	}

	c.Redirect(302, loginURL)
	c.Abort()
}
