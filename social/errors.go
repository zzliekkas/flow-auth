package social

import (
	"fmt"
)

// ErrorCode 错误代码类型
type ErrorCode string

const (
	// ErrInvalidConfig 配置无效
	ErrInvalidConfig ErrorCode = "invalid_config"

	// ErrAuthorizationFailed 授权失败
	ErrAuthorizationFailed ErrorCode = "authorization_failed"

	// ErrTokenExchange 令牌交换失败
	ErrTokenExchange ErrorCode = "token_exchange_failed"

	// ErrUserInfoFailed 获取用户信息失败
	ErrUserInfoFailed ErrorCode = "user_info_failed"

	// ErrSignatureFailed 签名验证失败
	ErrSignatureFailed ErrorCode = "signature_failed"

	// ErrInvalidState 无效的状态
	ErrInvalidState ErrorCode = "invalid_state"

	// ErrInvalidCode 无效的授权码
	ErrInvalidCode ErrorCode = "invalid_code"

	// ErrInvalidToken 无效的令牌
	ErrInvalidToken ErrorCode = "invalid_token"

	// ErrInvalidSignature 无效的签名
	ErrInvalidSignature ErrorCode = "invalid_signature"

	// ErrProviderNotFound 提供者未找到
	ErrProviderNotFound ErrorCode = "provider_not_found"

	// ErrSessionExpired 会话过期
	ErrSessionExpired ErrorCode = "session_expired"

	// ErrSessionNotFound 会话不存在
	ErrSessionNotFound ErrorCode = "session_not_found"

	// ErrSessionInvalid 会话无效
	ErrSessionInvalid ErrorCode = "session_invalid"
)

// AuthError 认证错误
type AuthError struct {
	// 错误代码
	Code ErrorCode

	// 提供者名称
	Provider string

	// 错误消息
	Message string

	// 原始错误
	Cause error
}

// Error 实现error接口
func (e *AuthError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Provider, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Provider, e.Message)
}

// Unwrap 实现errors.Unwrap接口
func (e *AuthError) Unwrap() error {
	return e.Cause
}

// NewAuthError 创建新的认证错误
func NewAuthError(provider string, code ErrorCode, message string, cause error) *AuthError {
	return &AuthError{
		Code:     code,
		Provider: provider,
		Message:  message,
		Cause:    cause,
	}
}

// IsAuthError 判断是否为认证错误
func IsAuthError(err error) bool {
	_, ok := err.(*AuthError)
	return ok
}

// GetAuthError 获取认证错误（如果是）
func GetAuthError(err error) *AuthError {
	if authErr, ok := err.(*AuthError); ok {
		return authErr
	}
	return nil
}

// GetErrorCode 获取错误代码（如果是认证错误）
func GetErrorCode(err error) ErrorCode {
	if authErr := GetAuthError(err); authErr != nil {
		return authErr.Code
	}
	return ""
}

// IsErrorCode 判断错误是否为指定代码
func IsErrorCode(err error, code ErrorCode) bool {
	return GetErrorCode(err) == code
}
