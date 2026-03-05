package social

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisSessionStore 提供基于Redis的会话存储实现
type RedisSessionStore struct {
	client *redis.Client // Redis客户端
	prefix string        // 键前缀
	ctx    context.Context
}

// RedisStoreOption Redis存储配置选项
type RedisStoreOption func(*RedisSessionStore)

// WithKeyPrefix 设置键前缀
func WithKeyPrefix(prefix string) RedisStoreOption {
	return func(s *RedisSessionStore) {
		s.prefix = prefix
	}
}

// WithContext 设置上下文
func WithContext(ctx context.Context) RedisStoreOption {
	return func(s *RedisSessionStore) {
		s.ctx = ctx
	}
}

// NewRedisSessionStore 创建新的Redis会话存储
func NewRedisSessionStore(client *redis.Client, opts ...RedisStoreOption) *RedisSessionStore {
	store := &RedisSessionStore{
		client: client,
		prefix: "flow:session:",
		ctx:    context.Background(),
	}

	// 应用选项
	for _, opt := range opts {
		opt(store)
	}

	return store
}

// 生成Redis键
func (s *RedisSessionStore) key(sessionID string) string {
	return s.prefix + sessionID
}

// Save 实现SessionStore接口
func (s *RedisSessionStore) Save(session *Session) error {
	// 序列化会话数据
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("序列化会话数据失败: %w", err)
	}

	// 计算过期时间
	expiration := session.ExpiresAt.Sub(time.Now())
	if expiration <= 0 {
		return fmt.Errorf("会话已过期")
	}

	// 保存到Redis
	key := s.key(session.ID)
	err = s.client.Set(s.ctx, key, data, expiration).Err()
	if err != nil {
		return fmt.Errorf("保存会话到Redis失败: %w", err)
	}

	return nil
}

// Get 实现SessionStore接口
func (s *RedisSessionStore) Get(id string) (*Session, error) {
	// 从Redis获取数据
	key := s.key(id)
	data, err := s.client.Get(s.ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, NewAuthError("", ErrSessionNotFound, "会话不存在", nil)
		}
		return nil, fmt.Errorf("从Redis获取会话失败: %w", err)
	}

	// 反序列化会话数据
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("反序列化会话数据失败: %w", err)
	}

	// 检查会话是否过期
	if time.Now().After(session.ExpiresAt) {
		s.Delete(id) // 删除过期会话
		return nil, NewAuthError("", ErrSessionExpired, "会话已过期", nil)
	}

	return &session, nil
}

// Delete 实现SessionStore接口
func (s *RedisSessionStore) Delete(id string) error {
	key := s.key(id)
	err := s.client.Del(s.ctx, key).Err()
	if err != nil {
		return fmt.Errorf("从Redis删除会话失败: %w", err)
	}
	return nil
}

// Clear 实现SessionStore接口
func (s *RedisSessionStore) Clear() error {
	// 使用SCAN命令查找所有会话键
	pattern := s.key("*")
	iter := s.client.Scan(s.ctx, 0, pattern, 0).Iterator()

	// 批量删除找到的键
	var keys []string
	for iter.Next(s.ctx) {
		keys = append(keys, iter.Val())
		// 每批1000个键执行一次删除
		if len(keys) >= 1000 {
			if err := s.client.Del(s.ctx, keys...).Err(); err != nil {
				return fmt.Errorf("批量删除会话失败: %w", err)
			}
			keys = keys[:0]
		}
	}

	// 删除剩余的键
	if len(keys) > 0 {
		if err := s.client.Del(s.ctx, keys...).Err(); err != nil {
			return fmt.Errorf("批量删除会话失败: %w", err)
		}
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("扫描会话键失败: %w", err)
	}

	return nil
}
