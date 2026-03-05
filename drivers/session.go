package drivers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zzliekkas/flow/v2"
	"github.com/zzliekkas/flow-auth"
)

// SessionStorage 定义会话存储接口
type SessionStorage interface {
	// Get 获取会话数据
	Get(id string) ([]byte, error)

	// Set 设置会话数据
	Set(id string, data []byte, expiry time.Duration) error

	// Delete 删除会话
	Delete(id string) error

	// Exists 检查会话是否存在
	Exists(id string) bool

	// Touch 刷新会话过期时间
	Touch(id string, expiry time.Duration) error
}

// MemorySessionStorage 内存会话存储实现
type MemorySessionStorage struct {
	sessions map[string]sessionData
}

type sessionData struct {
	data       []byte
	expireTime time.Time
}

// NewMemorySessionStorage 创建新的内存会话存储
func NewMemorySessionStorage() *MemorySessionStorage {
	return &MemorySessionStorage{
		sessions: make(map[string]sessionData),
	}
}

// Get 获取会话数据
func (s *MemorySessionStorage) Get(id string) ([]byte, error) {
	if data, ok := s.sessions[id]; ok {
		if time.Now().After(data.expireTime) {
			delete(s.sessions, id)
			return nil, auth.ErrInvalidToken
		}
		return data.data, nil
	}
	return nil, auth.ErrInvalidToken
}

// Set 设置会话数据
func (s *MemorySessionStorage) Set(id string, data []byte, expiry time.Duration) error {
	s.sessions[id] = sessionData{
		data:       data,
		expireTime: time.Now().Add(expiry),
	}
	return nil
}

// Delete 删除会话
func (s *MemorySessionStorage) Delete(id string) error {
	delete(s.sessions, id)
	return nil
}

// Exists 检查会话是否存在
func (s *MemorySessionStorage) Exists(id string) bool {
	data, ok := s.sessions[id]
	if !ok {
		return false
	}
	if time.Now().After(data.expireTime) {
		delete(s.sessions, id)
		return false
	}
	return true
}

// Touch 刷新会话过期时间
func (s *MemorySessionStorage) Touch(id string, expiry time.Duration) error {
	if data, ok := s.sessions[id]; ok {
		data.expireTime = time.Now().Add(expiry)
		s.sessions[id] = data
		return nil
	}
	return auth.ErrInvalidToken
}

// SessionConfig 会话配置
type SessionConfig struct {
	// CookieName 会话Cookie名称
	CookieName string

	// CookiePath Cookie路径
	CookiePath string

	// CookieDomain Cookie域
	CookieDomain string

	// CookieSecure 是否仅通过HTTPS发送
	CookieSecure bool

	// CookieHTTPOnly 是否仅可通过HTTP访问
	CookieHTTPOnly bool

	// DefaultExpiry 默认过期时间
	DefaultExpiry time.Duration

	// SameSite Cookie的SameSite属性
	SameSite http.SameSite
}

// DefaultSessionConfig 返回默认会话配置
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		CookieName:     "flow_session",
		CookiePath:     "/",
		CookieHTTPOnly: true,
		DefaultExpiry:  24 * time.Hour,
		SameSite:       http.SameSiteLaxMode,
	}
}

// SessionProvider 会话认证提供者
type SessionProvider struct {
	// 用户提供者
	userProvider auth.UserProvider

	// 会话存储
	storage SessionStorage

	// 会话配置
	config SessionConfig
}

// NewSessionProvider 创建新的会话认证提供者
func NewSessionProvider(userProvider auth.UserProvider, storage SessionStorage) *SessionProvider {
	return &SessionProvider{
		userProvider: userProvider,
		storage:      storage,
		config:       DefaultSessionConfig(),
	}
}

// ConfigureSession 配置会话提供者
func (p *SessionProvider) ConfigureSession(config SessionConfig) {
	p.config = config
}

// Authenticate 验证用户凭证并返回已认证用户
func (p *SessionProvider) Authenticate(ctx context.Context, credentials map[string]string) (auth.Authenticatable, error) {
	// 通过用户提供者获取用户
	user, err := p.userProvider.FindByCredentials(ctx, credentials)
	if err != nil {
		return nil, err
	}

	// 验证用户凭证
	valid, err := p.userProvider.ValidateCredentials(ctx, user, credentials)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, auth.ErrInvalidCredentials
	}

	return user, nil
}

// GetUserByID 通过ID获取用户
func (p *SessionProvider) GetUserByID(ctx context.Context, id string) (auth.Authenticatable, error) {
	return p.userProvider.FindByID(ctx, id)
}

// GenerateToken 为用户生成会话令牌并存储会话数据
func (p *SessionProvider) GenerateToken(ctx context.Context, user auth.Authenticatable, expiry time.Duration) (string, error) {
	// 创建会话ID
	sessionID := generateSessionID()

	// 创建会话数据
	sessionData := map[string]interface{}{
		"user_id":     user.GetAuthIdentifier(),
		"username":    user.GetAuthUsername(),
		"permissions": user.GetPermissions(),
		"roles":       user.GetRoles(),
		"created_at":  time.Now().Unix(),
	}

	// 序列化会话数据
	data, err := json.Marshal(sessionData)
	if err != nil {
		return "", err
	}

	// 存储会话数据
	if err := p.storage.Set(sessionID, data, expiry); err != nil {
		return "", err
	}

	return sessionID, nil
}

// ValidateToken 验证会话令牌并返回关联的用户
func (p *SessionProvider) ValidateToken(ctx context.Context, token string) (auth.Authenticatable, error) {
	// 获取会话数据
	data, err := p.storage.Get(token)
	if err != nil {
		return nil, auth.ErrInvalidToken
	}

	// 解析会话数据
	var sessionData map[string]interface{}
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, auth.ErrInvalidToken
	}

	// 获取用户ID
	userID, ok := sessionData["user_id"].(string)
	if !ok {
		return nil, auth.ErrInvalidToken
	}

	// 刷新会话过期时间
	if err := p.storage.Touch(token, p.config.DefaultExpiry); err != nil {
		return nil, err
	}

	// 通过ID获取用户
	return p.GetUserByID(ctx, userID)
}

// RefreshToken 刷新会话令牌
func (p *SessionProvider) RefreshToken(ctx context.Context, token string) (string, error) {
	// 获取会话数据
	data, err := p.storage.Get(token)
	if err != nil {
		return "", auth.ErrInvalidToken
	}

	// 解析会话数据
	var sessionData map[string]interface{}
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return "", auth.ErrInvalidToken
	}

	// 获取用户ID
	userID, ok := sessionData["user_id"].(string)
	if !ok {
		return "", auth.ErrInvalidToken
	}

	// 通过ID获取用户
	user, err := p.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}

	// 删除旧会话
	if err := p.storage.Delete(token); err != nil {
		return "", err
	}

	// 生成新会话
	return p.GenerateToken(ctx, user, p.config.DefaultExpiry)
}

// InvalidateToken 使会话令牌失效
func (p *SessionProvider) InvalidateToken(ctx context.Context, token string) error {
	return p.storage.Delete(token)
}

// CheckPermission 检查用户是否拥有指定权限
func (p *SessionProvider) CheckPermission(ctx context.Context, user auth.Authenticatable, permission string) bool {
	permissions := user.GetPermissions()
	for _, userPerm := range permissions {
		if userPerm == permission || userPerm == "*" {
			return true
		}
	}
	return false
}

// CheckRole 检查用户是否拥有指定角色
func (p *SessionProvider) CheckRole(ctx context.Context, user auth.Authenticatable, role string) bool {
	roles := user.GetRoles()
	for _, userRole := range roles {
		if userRole == role {
			return true
		}
	}
	return false
}

// ToMiddleware 将会话提供者转换为Flow中间件
func (p *SessionProvider) ToMiddleware() flow.HandlerFunc {
	return func(c *flow.Context) {
		// 获取会话ID
		sessionID, _ := c.Cookie(p.config.CookieName)
		if sessionID == "" {
			c.Next()
			return
		}

		// 验证会话
		user, err := p.ValidateToken(c.Request.Context(), sessionID)
		if err != nil {
			// 会话无效，删除Cookie
			c.SetCookie(p.config.CookieName, "", -1, p.config.CookiePath, p.config.CookieDomain, p.config.CookieSecure, p.config.CookieHTTPOnly)
			c.Next()
			return
		}

		// 将用户添加到上下文
		ctx := auth.WithUser(c.Request.Context(), user)
		ctx = auth.WithToken(ctx, sessionID)
		c.Request = c.Request.WithContext(ctx)

		// 将用户添加到Flow上下文
		c.Set("auth_user", user)

		c.Next()
	}
}

// 生成唯一的会话ID
func generateSessionID() string {
	// 实际实现应使用更安全的随机数生成方法
	return "session_" + time.Now().Format("20060102150405") + "_" + randomString(16)
}

// 生成随机字符串
func randomString(length int) string {
	// 简化实现，实际应使用crypto/rand
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().Nanosecond()%len(charset)]
		time.Sleep(time.Nanosecond)
	}
	return string(result)
}
