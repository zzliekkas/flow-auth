package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/zzliekkas/flow-auth/v3"
)

// 上下文键
type contextKey string

const (
	// UserContextKey 用户上下文键
	UserContextKey contextKey = "auth_user"

	// TokenContextKey 令牌上下文键
	TokenContextKey contextKey = "auth_token"
)

// Options JWT中间件配置选项
type Options struct {
	// Provider 认证提供者
	Provider auth.Provider

	// TokenLookup 令牌查找位置，格式: "header:Authorization,query:token,cookie:jwt"
	TokenLookup string

	// AuthScheme 认证方案，例如: "Bearer"
	AuthScheme string

	// SkipRoutes 跳过认证的路由
	SkipRoutes []string
}

// DefaultOptions 返回默认中间件选项
func DefaultOptions() Options {
	return Options{
		TokenLookup: "header:Authorization",
		AuthScheme:  "Bearer",
	}
}

// JWTMiddleware JWT认证中间件
type JWTMiddleware struct {
	options Options
}

// NewJWTMiddleware 创建新的JWT中间件
func NewJWTMiddleware(options Options) *JWTMiddleware {
	if options.TokenLookup == "" {
		options.TokenLookup = "header:Authorization"
	}

	if options.AuthScheme == "" {
		options.AuthScheme = "Bearer"
	}

	return &JWTMiddleware{
		options: options,
	}
}

// Middleware 返回HTTP中间件函数
func (m *JWTMiddleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 检查是否需要跳过当前路由
			if m.shouldSkip(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// 获取令牌
			token, err := m.extractToken(r)
			if err != nil {
				http.Error(w, "无法获取认证令牌", http.StatusUnauthorized)
				return
			}

			// 验证令牌
			user, err := m.options.Provider.ValidateToken(r.Context(), token)
			if err != nil {
				http.Error(w, "认证失败："+err.Error(), http.StatusUnauthorized)
				return
			}

			// 将用户和令牌存储到上下文中
			ctx := context.WithValue(r.Context(), UserContextKey, user)
			ctx = context.WithValue(ctx, TokenContextKey, token)

			// 使用新的上下文继续处理请求
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission 创建权限检查中间件
func (m *JWTMiddleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 从上下文中获取用户
			user, ok := r.Context().Value(UserContextKey).(auth.Authenticatable)
			if !ok {
				http.Error(w, "用户未认证", http.StatusUnauthorized)
				return
			}

			// 检查权限
			hasPermission := m.options.Provider.CheckPermission(r.Context(), user, permission)
			if !hasPermission {
				http.Error(w, "权限不足", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole 创建角色检查中间件
func (m *JWTMiddleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 从上下文中获取用户
			user, ok := r.Context().Value(UserContextKey).(auth.Authenticatable)
			if !ok {
				http.Error(w, "用户未认证", http.StatusUnauthorized)
				return
			}

			// 检查角色
			hasRole := m.options.Provider.CheckRole(r.Context(), user, role)
			if !hasRole {
				http.Error(w, "角色不足", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractToken 从请求中提取令牌
func (m *JWTMiddleware) extractToken(r *http.Request) (string, error) {
	lookups := strings.Split(m.options.TokenLookup, ",")

	for _, lookup := range lookups {
		parts := strings.SplitN(lookup, ":", 2)
		if len(parts) != 2 {
			continue
		}

		method := parts[0]
		source := parts[1]

		switch method {
		case "header":
			return m.extractTokenFromHeader(r, source)
		case "query":
			return m.extractTokenFromQuery(r, source)
		case "cookie":
			return m.extractTokenFromCookie(r, source)
		}
	}

	return "", auth.ErrUnauthorized
}

// extractTokenFromHeader 从请求头中提取令牌
func (m *JWTMiddleware) extractTokenFromHeader(r *http.Request, header string) (string, error) {
	authHeader := r.Header.Get(header)
	if authHeader == "" {
		return "", auth.ErrUnauthorized
	}

	if m.options.AuthScheme != "" {
		l := len(m.options.AuthScheme)
		if len(authHeader) > l+1 && authHeader[:l] == m.options.AuthScheme {
			return authHeader[l+1:], nil
		}
		return "", auth.ErrUnauthorized
	}

	return authHeader, nil
}

// extractTokenFromQuery 从查询参数中提取令牌
func (m *JWTMiddleware) extractTokenFromQuery(r *http.Request, param string) (string, error) {
	token := r.URL.Query().Get(param)
	if token == "" {
		return "", auth.ErrUnauthorized
	}
	return token, nil
}

// extractTokenFromCookie 从Cookie中提取令牌
func (m *JWTMiddleware) extractTokenFromCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", auth.ErrUnauthorized
	}
	return cookie.Value, nil
}

// shouldSkip 检查是否应该跳过当前路由的认证
func (m *JWTMiddleware) shouldSkip(path string) bool {
	for _, p := range m.options.SkipRoutes {
		if p == path {
			return true
		}
	}
	return false
}

// GetAuthenticatedUser 获取认证用户
func GetAuthenticatedUser(ctx context.Context) (auth.Authenticatable, bool) {
	user, ok := ctx.Value(UserContextKey).(auth.Authenticatable)
	return user, ok
}

// GetToken 获取认证令牌
func GetToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(TokenContextKey).(string)
	return token, ok
}
