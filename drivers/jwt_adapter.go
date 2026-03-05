package drivers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/zzliekkas/flow-auth"
	"github.com/zzliekkas/flow/v2"
	"github.com/zzliekkas/flow/v2/middleware"
)

// TokenBlacklist 定义令牌黑名单接口
type TokenBlacklist interface {
	// Add 将令牌添加到黑名单
	Add(token string, expiry time.Time) error

	// Contains 检查令牌是否在黑名单中
	Contains(token string) bool

	// Cleanup 清理已过期的令牌
	Cleanup()
}

// MemoryBlacklist 是基于内存的令牌黑名单实现
type MemoryBlacklist struct {
	blacklist map[string]time.Time
	mu        sync.RWMutex
}

// NewMemoryBlacklist 创建新的内存黑名单
func NewMemoryBlacklist() *MemoryBlacklist {
	return &MemoryBlacklist{
		blacklist: make(map[string]time.Time),
	}
}

// Add 将令牌添加到黑名单
func (m *MemoryBlacklist) Add(token string, expiry time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blacklist[token] = expiry
	return nil
}

// Contains 检查令牌是否在黑名单中
func (m *MemoryBlacklist) Contains(token string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	expiryTime, exists := m.blacklist[token]
	if !exists {
		return false
	}

	// 已过期的令牌视为不在黑名单中，由 Cleanup() 定期清理
	if time.Now().After(expiryTime) {
		return false
	}

	return true
}

// Cleanup 清理已过期的令牌
func (m *MemoryBlacklist) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for token, expiry := range m.blacklist {
		if now.After(expiry) {
			delete(m.blacklist, token)
		}
	}
}

// JWTConfig JWT配置
type JWTConfig struct {
	// SigningKey 签名密钥
	SigningKey []byte

	// SigningMethod 签名方法
	SigningMethod jwt.SigningMethod

	// Issuer 令牌发行者
	Issuer string

	// Audience 目标接收者
	Audience []string

	// DefaultExpiry 默认过期时间
	DefaultExpiry time.Duration

	// RefreshExpiry 刷新令牌过期时间
	RefreshExpiry time.Duration
}

// DefaultJWTConfig 返回默认JWT配置
// 注意: 必须设置 SigningKey，否则令牌签名不安全
func DefaultJWTConfig() JWTConfig {
	return JWTConfig{
		SigningKey:    nil,
		SigningMethod: jwt.SigningMethodHS256,
		Issuer:        "flow-auth",
		Audience:      []string{"flow-api"},
		DefaultExpiry: 24 * time.Hour,
		RefreshExpiry: 7 * 24 * time.Hour,
	}
}

// JWTProvider 是基于JWT的认证提供者实现
type JWTProvider struct {
	// 用户提供者
	userProvider auth.UserProvider

	// JWT配置
	jwtConfig middleware.JWTConfig

	// 自定义JWT配置
	customConfig JWTConfig

	// 令牌黑名单
	blacklist TokenBlacklist

	// 签名密钥
	signingKey interface{}

	// 签名方法
	signingMethod jwt.SigningMethod
}

// NewJWTProvider 创建新的JWT认证提供者
func NewJWTProvider(userProvider auth.UserProvider, signingKey interface{}, method jwt.SigningMethod) *JWTProvider {
	// 创建默认JWT配置
	jwtConfig := middleware.DefaultJWTConfig()
	jwtConfig.SigningKey = signingKey
	jwtConfig.SigningMethod = method

	// 创建自定义JWT配置
	customConfig := DefaultJWTConfig()

	return &JWTProvider{
		userProvider:  userProvider,
		jwtConfig:     jwtConfig,
		customConfig:  customConfig,
		blacklist:     NewMemoryBlacklist(),
		signingKey:    signingKey,
		signingMethod: method,
	}
}

// ConfigureJWT 配置JWT提供者
func (p *JWTProvider) ConfigureJWT(config middleware.JWTConfig) {
	p.jwtConfig = config
}

// SetBlacklist 设置令牌黑名单
func (p *JWTProvider) SetBlacklist(blacklist TokenBlacklist) {
	p.blacklist = blacklist
}

// Authenticate 验证用户凭证并返回已认证用户
func (p *JWTProvider) Authenticate(ctx context.Context, credentials map[string]string) (auth.Authenticatable, error) {
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
func (p *JWTProvider) GetUserByID(ctx context.Context, id string) (auth.Authenticatable, error) {
	return p.userProvider.FindByID(ctx, id)
}

// GenerateToken 为用户生成JWT令牌
func (p *JWTProvider) GenerateToken(ctx context.Context, user auth.Authenticatable, expiry time.Duration) (string, error) {
	// 创建令牌声明
	claims := &auth.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.GetAuthIdentifier(),
			Issuer:    "flow",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
		},
		UserID:      user.GetAuthIdentifier(),
		Username:    user.GetAuthUsername(),
		Permissions: user.GetPermissions(),
		Roles:       user.GetRoles(),
	}

	// 创建令牌
	token := jwt.NewWithClaims(p.signingMethod, claims)

	// 签名令牌
	tokenString, err := token.SignedString(p.signingKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateToken 验证JWT令牌并返回关联的用户
func (p *JWTProvider) ValidateToken(ctx context.Context, tokenString string) (auth.Authenticatable, error) {
	// 检查令牌是否在黑名单中
	if p.blacklist.Contains(tokenString) {
		return nil, auth.ErrInvalidToken
	}

	// 解析令牌
	token, err := jwt.ParseWithClaims(tokenString, &auth.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法
		if token.Method.Alg() != p.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.signingKey, nil
	})

	if err != nil {
		return nil, auth.ErrInvalidToken
	}

	if !token.Valid {
		return nil, auth.ErrInvalidToken
	}

	// 从令牌中提取声明
	claims, ok := token.Claims.(*auth.TokenClaims)
	if !ok {
		return nil, auth.ErrInvalidToken
	}

	// 获取用户ID
	userID := claims.Subject
	if userID == "" {
		return nil, auth.ErrInvalidToken
	}

	// 通过ID获取用户
	user, err := p.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// RefreshToken 刷新JWT令牌
func (p *JWTProvider) RefreshToken(ctx context.Context, tokenString string) (string, error) {
	// 不验证过期时间的令牌解析
	token, err := jwt.ParseWithClaims(tokenString, &auth.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != p.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.signingKey, nil
	}, jwt.WithoutClaimsValidation())

	if err != nil {
		return "", auth.ErrInvalidToken
	}

	// 获取令牌声明
	claims, ok := token.Claims.(*auth.TokenClaims)
	if !ok {
		return "", auth.ErrInvalidToken
	}

	// 获取用户
	user, err := p.userProvider.FindByID(ctx, claims.UserID)
	if err != nil {
		return "", err
	}

	// 将旧令牌加入黑名单
	expiryTime := time.Unix(claims.ExpiresAt.Unix(), 0)
	if err := p.blacklist.Add(tokenString, expiryTime); err != nil {
		return "", err
	}

	// 生成新令牌
	return p.GenerateToken(ctx, user, p.customConfig.DefaultExpiry)
}

// InvalidateToken 使JWT令牌失效
func (p *JWTProvider) InvalidateToken(ctx context.Context, tokenString string) error {
	// 解析令牌以获取过期时间
	token, err := jwt.ParseWithClaims(tokenString, &auth.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return p.signingKey, nil
	}, jwt.WithoutClaimsValidation())

	if err != nil {
		return auth.ErrInvalidToken
	}

	claims, ok := token.Claims.(*auth.TokenClaims)
	if !ok {
		return auth.ErrInvalidToken
	}

	// 将令牌加入黑名单
	expiryTime := time.Unix(claims.ExpiresAt.Unix(), 0)
	return p.blacklist.Add(tokenString, expiryTime)
}

// CheckPermission 检查用户是否拥有指定权限
func (p *JWTProvider) CheckPermission(ctx context.Context, user auth.Authenticatable, permission string) bool {
	// 获取用户权限
	permissions := user.GetPermissions()
	for _, userPerm := range permissions {
		if userPerm == permission || userPerm == "*" {
			return true
		}
	}

	return false
}

// CheckRole 检查用户是否拥有指定角色
func (p *JWTProvider) CheckRole(ctx context.Context, user auth.Authenticatable, role string) bool {
	// 获取用户角色
	roles := user.GetRoles()
	for _, userRole := range roles {
		if userRole == role {
			return true
		}
	}

	return false
}

// ToMiddleware 将JWT提供者转换为Flow中间件
func (p *JWTProvider) ToMiddleware() flow.HandlerFunc {
	// 创建JWT中间件
	jwtMiddleware := middleware.JWTWithConfig(p.jwtConfig)

	return jwtMiddleware
}
