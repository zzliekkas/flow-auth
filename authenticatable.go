package auth

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 定义错误常量
var (
	// ErrInvalidCredentials 表示提供的凭证无效
	ErrInvalidCredentials = errors.New("提供的凭证无效")

	// ErrInvalidToken 表示提供的令牌无效
	ErrInvalidToken = errors.New("提供的令牌无效或已过期")

	// ErrUserNotFound 表示未找到请求的用户
	ErrUserNotFound = errors.New("未找到用户")

	// ErrUnauthorized 表示用户未经授权访问资源
	ErrUnauthorized = errors.New("未经授权访问")
)

// Authenticatable 表示可以被认证的实体
type Authenticatable interface {
	// GetAuthIdentifier 返回实体的唯一标识符
	GetAuthIdentifier() string

	// GetAuthUsername 返回实体的用户名
	GetAuthUsername() string

	// GetPermissions 返回实体拥有的权限列表
	GetPermissions() []string

	// GetRoles 返回实体拥有的角色列表
	GetRoles() []string
}

// TokenClaims 表示JWT令牌声明
type TokenClaims struct {
	jwt.RegisteredClaims

	// UserID 是用户的唯一标识符
	UserID string `json:"user_id"`

	// Username 是用户的用户名
	Username string `json:"username"`

	// Permissions 是用户的权限列表
	Permissions []string `json:"permissions,omitempty"`

	// Roles 是用户的角色列表
	Roles []string `json:"roles,omitempty"`

	// 其他自定义字段可以根据需要添加
}

// UserProvider 定义用户数据访问接口
type UserProvider interface {
	// FindByID 通过ID查找用户
	FindByID(ctx context.Context, id string) (Authenticatable, error)

	// FindByCredentials 通过凭证查找用户
	FindByCredentials(ctx context.Context, credentials map[string]string) (Authenticatable, error)

	// ValidateCredentials 验证用户的凭证
	ValidateCredentials(ctx context.Context, user Authenticatable, credentials map[string]string) (bool, error)
}

// Provider 表示认证服务提供者
// Deprecated: 请使用 AuthProvider 接口，Provider 将在未来版本移除
type Provider interface {
	// Authenticate 验证用户凭证并返回已认证用户
	Authenticate(ctx context.Context, credentials map[string]string) (Authenticatable, error)

	// GetUserByID 通过ID获取用户
	GetUserByID(ctx context.Context, id string) (Authenticatable, error)

	// GenerateToken 为用户生成认证令牌
	GenerateToken(ctx context.Context, user Authenticatable, expiry time.Duration) (string, error)

	// ValidateToken 验证令牌并返回关联的用户
	ValidateToken(ctx context.Context, token string) (Authenticatable, error)

	// RefreshToken 刷新认证令牌
	RefreshToken(ctx context.Context, token string) (string, error)

	// InvalidateToken 使令牌失效
	InvalidateToken(ctx context.Context, token string) error

	// CheckPermission 检查用户是否拥有指定权限
	CheckPermission(ctx context.Context, user Authenticatable, permission string) bool

	// CheckRole 检查用户是否拥有指定角色
	CheckRole(ctx context.Context, user Authenticatable, role string) bool
}

// AuthProvider 定义了认证提供者的接口
type AuthProvider interface {
	// Authenticate 验证用户凭证并返回认证实体
	Authenticate(ctx context.Context, credentials map[string]string) (Authenticatable, error)

	// GetUserByID 根据ID获取认证实体
	GetUserByID(ctx context.Context, id string) (Authenticatable, error)

	// GetUserByIdentifier 根据标识符获取认证实体
	GetUserByIdentifier(ctx context.Context, identifier string) (Authenticatable, error)

	// GenerateToken 为认证实体生成令牌
	GenerateToken(ctx context.Context, user Authenticatable, expiry time.Duration) (string, error)

	// ValidateToken 验证令牌并返回认证实体
	ValidateToken(ctx context.Context, token string) (Authenticatable, error)

	// RefreshToken 刷新令牌
	RefreshToken(ctx context.Context, token string) (string, error)

	// InvalidateToken 使令牌失效
	InvalidateToken(ctx context.Context, token string) error

	// CheckPermission 检查认证实体是否拥有指定权限
	CheckPermission(ctx context.Context, user Authenticatable, permission string) bool

	// CheckRole 检查认证实体是否拥有指定角色
	CheckRole(ctx context.Context, user Authenticatable, role string) bool
}

// AuthenticatableUser 是Authenticatable接口的基本实现，可以嵌入到用户模型中
type AuthenticatableUser struct {
	ID          string   `json:"id"`
	Identifier  string   `json:"identifier"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	Status      bool     `json:"status"`
}

// GetAuthID 实现Authenticatable接口
func (u *AuthenticatableUser) GetAuthID() string {
	return u.ID
}

// GetAuthIdentifier 实现Authenticatable接口
func (u *AuthenticatableUser) GetAuthIdentifier() string {
	return u.Identifier
}

// GetAuthUsername 实现Authenticatable接口
func (u *AuthenticatableUser) GetAuthUsername() string {
	return u.Identifier
}

// GetAuthPassword 返回密码
func (u *AuthenticatableUser) GetAuthPassword() string {
	return u.Password
}

// GetPermissions 实现Authenticatable接口
func (u *AuthenticatableUser) GetPermissions() []string {
	return u.Permissions
}

// GetRoles 实现Authenticatable接口
func (u *AuthenticatableUser) GetRoles() []string {
	return u.Roles
}

// IsActive 检查用户是否活跃
func (u *AuthenticatableUser) IsActive() bool {
	return u.Status
}

// AuthContext 是认证上下文的键类型
type AuthContext string

// 认证上下文中的键名常量
const (
	// AuthUserKey 是存储在上下文中的已认证用户的键
	AuthUserKey AuthContext = "auth_user"

	// AuthTokenKey 是存储在上下文中的认证令牌的键
	AuthTokenKey AuthContext = "auth_token"

	// AuthProviderKey 是存储在上下文中的认证提供者的键
	AuthProviderKey AuthContext = "auth_provider"
)

// WithUser 将认证用户添加到上下文中
func WithUser(ctx context.Context, user Authenticatable) context.Context {
	return context.WithValue(ctx, AuthUserKey, user)
}

// UserFromContext 从上下文中获取认证用户
func UserFromContext(ctx context.Context) (Authenticatable, bool) {
	user, ok := ctx.Value(AuthUserKey).(Authenticatable)
	return user, ok
}

// WithToken 将认证令牌添加到上下文中
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, AuthTokenKey, token)
}

// TokenFromContext 从上下文中获取认证令牌
func TokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(AuthTokenKey).(string)
	return token, ok
}

// WithProvider 将认证提供者添加到上下文中
func WithProvider(ctx context.Context, provider AuthProvider) context.Context {
	return context.WithValue(ctx, AuthProviderKey, provider)
}

// ProviderFromContext 从上下文中获取认证提供者
func ProviderFromContext(ctx context.Context) (AuthProvider, bool) {
	provider, ok := ctx.Value(AuthProviderKey).(AuthProvider)
	return provider, ok
}
