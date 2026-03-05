package auth

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/zzliekkas/flow/v2"
)

// 策略相关错误
var (
	// ErrPolicyNotFound 表示找不到请求的策略
	ErrPolicyNotFound = errors.New("找不到策略")

	// ErrInvalidPolicyHandler 表示策略处理器无效
	ErrInvalidPolicyHandler = errors.New("无效的策略处理器")
)

// PolicyHandler 是策略处理函数类型
type PolicyHandler func(ctx context.Context, user Authenticatable, resource interface{}, action string) bool

// ResourcePolicy 定义资源策略接口
type ResourcePolicy interface {
	// Name 返回策略名称
	Name() string

	// Resource 返回策略适用的资源类型名称
	Resource() string

	// Check 检查用户是否对资源有执行操作的权限
	Check(ctx context.Context, user Authenticatable, resource interface{}, action string) bool
}

// BasePolicy 提供策略的基本实现
type BasePolicy struct {
	// 策略名称
	name string

	// 资源类型
	resource string

	// 允许的动作
	allowedActions map[string]PolicyHandler

	// 动作别名
	actionAliases map[string]string
}

// NewBasePolicy 创建新的基本策略
func NewBasePolicy(name, resource string) *BasePolicy {
	return &BasePolicy{
		name:           name,
		resource:       resource,
		allowedActions: make(map[string]PolicyHandler),
		actionAliases:  make(map[string]string),
	}
}

// Name 返回策略名称
func (p *BasePolicy) Name() string {
	return p.name
}

// Resource 返回策略适用的资源类型名称
func (p *BasePolicy) Resource() string {
	return p.resource
}

// RegisterAction 注册可对资源执行的操作及其处理函数
func (p *BasePolicy) RegisterAction(action string, handler PolicyHandler) {
	p.allowedActions[strings.ToLower(action)] = handler
}

// RegisterActionAlias 注册操作的别名
func (p *BasePolicy) RegisterActionAlias(action, alias string) {
	p.actionAliases[strings.ToLower(alias)] = strings.ToLower(action)
}

// Check 检查用户是否对资源有执行操作的权限
func (p *BasePolicy) Check(ctx context.Context, user Authenticatable, resource interface{}, action string) bool {
	action = strings.ToLower(action)

	// 检查是否是别名
	if mainAction, isAlias := p.actionAliases[action]; isAlias {
		action = mainAction
	}

	// 查找处理函数
	handler, ok := p.allowedActions[action]
	if !ok {
		return false
	}

	// 执行权限检查
	return handler(ctx, user, resource, action)
}

// PolicyManager 管理注册的策略
type PolicyManager struct {
	// 注册的策略
	policies map[string]ResourcePolicy

	// 资源类型到策略的映射
	resourcePolicies map[string][]ResourcePolicy

	// 互斥锁
	mu sync.RWMutex
}

// NewPolicyManager 创建新的策略管理器
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		policies:         make(map[string]ResourcePolicy),
		resourcePolicies: make(map[string][]ResourcePolicy),
	}
}

// RegisterPolicy 注册新策略
func (m *PolicyManager) RegisterPolicy(policy ResourcePolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 存储策略
	m.policies[policy.Name()] = policy

	// 更新资源到策略的映射
	resource := policy.Resource()
	m.resourcePolicies[resource] = append(m.resourcePolicies[resource], policy)
}

// GetPolicy 获取指定名称的策略
func (m *PolicyManager) GetPolicy(name string) (ResourcePolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policy, ok := m.policies[name]
	if !ok {
		return nil, ErrPolicyNotFound
	}

	return policy, nil
}

// GetPoliciesForResource 获取适用于资源类型的所有策略
func (m *PolicyManager) GetPoliciesForResource(resourceType string) []ResourcePolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.resourcePolicies[resourceType]
}

// Check 检查用户是否有权限对资源执行操作
func (m *PolicyManager) Check(ctx context.Context, user Authenticatable, resource interface{}, action string) bool {
	// 获取资源类型
	resourceType := getResourceType(resource)

	// 获取适用于该资源的所有策略
	policies := m.GetPoliciesForResource(resourceType)
	if len(policies) == 0 {
		return false
	}

	// 至少有一个策略通过即可
	for _, policy := range policies {
		if policy.Check(ctx, user, resource, action) {
			return true
		}
	}

	return false
}

// Can 检查用户是否能执行特定操作
func (m *PolicyManager) Can(ctx context.Context, user Authenticatable, action string, resource interface{}) bool {
	return m.Check(ctx, user, resource, action)
}

// Cannot 检查用户是否不能执行特定操作
func (m *PolicyManager) Cannot(ctx context.Context, user Authenticatable, action string, resource interface{}) bool {
	return !m.Can(ctx, user, action, resource)
}

// Authorize 检查授权并返回错误
func (m *PolicyManager) Authorize(ctx context.Context, user Authenticatable, action string, resource interface{}) error {
	if m.Cannot(ctx, user, action, resource) {
		return ErrPermissionDenied
	}
	return nil
}

// getResourceType 获取资源的类型名称
func getResourceType(resource interface{}) string {
	t := reflect.TypeOf(resource)

	// 处理指针
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	return t.Name()
}

// === 常用策略快速创建函数 ===

// CreateOwnerPolicy 创建基于所有者的策略
// 当用户是资源的所有者时，允许执行操作
func CreateOwnerPolicy(policyName, resourceType string, getOwnerID func(resource interface{}) string) ResourcePolicy {
	policy := NewBasePolicy(policyName, resourceType)

	// 注册常见操作
	policy.RegisterAction("view", func(ctx context.Context, user Authenticatable, resource interface{}, action string) bool {
		userID := user.GetAuthIdentifier()
		ownerID := getOwnerID(resource)
		return userID == ownerID
	})

	policy.RegisterAction("edit", func(ctx context.Context, user Authenticatable, resource interface{}, action string) bool {
		userID := user.GetAuthIdentifier()
		ownerID := getOwnerID(resource)
		return userID == ownerID
	})

	policy.RegisterAction("delete", func(ctx context.Context, user Authenticatable, resource interface{}, action string) bool {
		userID := user.GetAuthIdentifier()
		ownerID := getOwnerID(resource)
		return userID == ownerID
	})

	// 注册别名
	policy.RegisterActionAlias("view", "read")
	policy.RegisterActionAlias("view", "show")
	policy.RegisterActionAlias("edit", "update")

	return policy
}

// CreateRoleBasedPolicy 创建基于角色的策略
// 根据用户角色和操作的映射关系进行授权
func CreateRoleBasedPolicy(policyName, resourceType string, roleActionMap map[string][]string) ResourcePolicy {
	policy := NewBasePolicy(policyName, resourceType)

	// 为每个操作创建策略处理函数
	actions := make(map[string][]string)

	// 反转映射，构建操作到角色的映射
	for role, roleActions := range roleActionMap {
		for _, action := range roleActions {
			action = strings.ToLower(action)
			actions[action] = append(actions[action], role)
		}
	}

	// 注册所有操作
	for action, roles := range actions {
		// 创建闭包捕获必要的变量
		requiredRoles := make([]string, len(roles))
		copy(requiredRoles, roles)

		policy.RegisterAction(action, func(ctx context.Context, user Authenticatable, resource interface{}, action string) bool {
			userRoles := user.GetRoles()

			// 检查用户是否拥有至少一个所需角色
			for _, userRole := range userRoles {
				for _, requiredRole := range requiredRoles {
					if userRole == requiredRole {
						return true
					}
				}
			}

			return false
		})
	}

	return policy
}

// CreatePermissionBasedPolicy 创建基于权限的策略
// 根据用户权限和操作的映射关系进行授权
func CreatePermissionBasedPolicy(policyName, resourceType string, permissionActionMap map[string][]string) ResourcePolicy {
	policy := NewBasePolicy(policyName, resourceType)

	// 为每个操作创建策略处理函数
	actions := make(map[string][]string)

	// 反转映射，构建操作到权限的映射
	for permission, permActions := range permissionActionMap {
		for _, action := range permActions {
			action = strings.ToLower(action)
			actions[action] = append(actions[action], permission)
		}
	}

	// 注册所有操作
	for action, permissions := range actions {
		// 创建闭包捕获必要的变量
		requiredPermissions := make([]string, len(permissions))
		copy(requiredPermissions, permissions)

		policy.RegisterAction(action, func(ctx context.Context, user Authenticatable, resource interface{}, action string) bool {
			userPermissions := user.GetPermissions()

			// 检查用户是否拥有至少一个所需权限
			for _, userPerm := range userPermissions {
				// 通配符权限
				if userPerm == "*" {
					return true
				}

				for _, requiredPerm := range requiredPermissions {
					if userPerm == requiredPerm {
						return true
					}
				}
			}

			return false
		})
	}

	return policy
}

// === 中间件支持 ===

// PolicyMiddleware 创建策略授权中间件
func (m *PolicyManager) PolicyMiddleware(action string, resourceProvider func(*flow.Context) interface{}) flow.HandlerFunc {
	return func(c *flow.Context) {
		// 从上下文获取用户
		user, exists := UserFromContext(c.Request.Context())
		if !exists {
			c.JSON(403, flow.H{
				"error": "未授权访问",
			})
			c.Abort()
			return
		}

		// 获取资源
		resource := resourceProvider(c)
		if resource == nil {
			c.JSON(404, flow.H{
				"error": "找不到资源",
			})
			c.Abort()
			return
		}

		// 检查授权
		if m.Cannot(c.Request.Context(), user, action, resource) {
			c.JSON(403, flow.H{
				"error": fmt.Sprintf("没有执行 %s 操作的权限", action),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
