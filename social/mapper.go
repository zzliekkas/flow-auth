package social

import (
	"github.com/zzliekkas/flow/v2"
)

// UserMapper 用户映射器接口
type UserMapper interface {
	// MapUser 将第三方用户信息映射到系统用户
	MapUser(ctx *flow.Context, userInfo *UserInfo) error
}

// DefaultUserMapper 默认用户映射器
type DefaultUserMapper struct {
	// 用户模型
	UserModel interface{}

	// 用户服务
	UserService interface{}

	// 自动创建用户
	AutoCreate bool

	// 自动更新用户
	AutoUpdate bool

	// 字段映射
	FieldMapping map[string]string
}

// NewDefaultUserMapper 创建默认用户映射器
func NewDefaultUserMapper(options ...UserMapperOption) *DefaultUserMapper {
	mapper := &DefaultUserMapper{
		AutoCreate:   true,
		AutoUpdate:   true,
		FieldMapping: make(map[string]string),
	}

	// 应用选项
	for _, opt := range options {
		opt(mapper)
	}

	return mapper
}

// UserMapperOption 用户映射器选项
type UserMapperOption func(*DefaultUserMapper)

// WithUserModel 设置用户模型
func WithUserModel(model interface{}) UserMapperOption {
	return func(m *DefaultUserMapper) {
		m.UserModel = model
	}
}

// WithUserService 设置用户服务
func WithUserService(service interface{}) UserMapperOption {
	return func(m *DefaultUserMapper) {
		m.UserService = service
	}
}

// WithAutoCreate 设置是否自动创建用户
func WithAutoCreate(autoCreate bool) UserMapperOption {
	return func(m *DefaultUserMapper) {
		m.AutoCreate = autoCreate
	}
}

// WithAutoUpdate 设置是否自动更新用户
func WithAutoUpdate(autoUpdate bool) UserMapperOption {
	return func(m *DefaultUserMapper) {
		m.AutoUpdate = autoUpdate
	}
}

// WithFieldMapping 设置字段映射
func WithFieldMapping(mapping map[string]string) UserMapperOption {
	return func(m *DefaultUserMapper) {
		for k, v := range mapping {
			m.FieldMapping[k] = v
		}
	}
}

// MapUser 实现UserMapper接口
func (m *DefaultUserMapper) MapUser(ctx *flow.Context, userInfo *UserInfo) error {
	// TODO: 实现用户映射逻辑
	// 1. 查找现有用户
	// 2. 如果不存在且允许自动创建，则创建新用户
	// 3. 如果存在且允许自动更新，则更新用户信息
	// 4. 处理用户关联（如绑定社交账号）
	return nil
}

// MapField 映射字段
func (m *DefaultUserMapper) MapField(fieldName string) string {
	if mapped, ok := m.FieldMapping[fieldName]; ok {
		return mapped
	}
	return fieldName
}
