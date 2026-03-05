package social

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Session 表示一个社交登录会话
type Session struct {
	ID        string                 `json:"id"`         // 会话ID
	Provider  string                 `json:"provider"`   // 提供者名称
	Token     string                 `json:"token"`      // 访问令牌
	UserInfo  map[string]interface{} `json:"user_info"`  // 用户信息
	CreatedAt time.Time              `json:"created_at"` // 创建时间
	ExpiresAt time.Time              `json:"expires_at"` // 过期时间
	Data      map[string]interface{} `json:"data"`       // 额外数据
}

// SessionStore 定义会话存储接口
// 框架使用者可以实现这个接口来提供自定义的存储后端
type SessionStore interface {
	// Save 保存会话
	Save(session *Session) error

	// Get 获取会话
	Get(id string) (*Session, error)

	// Delete 删除会话
	Delete(id string) error

	// Clear 清理所有会话
	Clear() error
}

// MemorySessionStore 提供基于内存的会话存储实现
// 这是一个默认实现，仅用于开发和测试
type MemorySessionStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewMemorySessionStore 创建新的内存会话存储
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*Session),
	}
}

// Save 实现SessionStore接口
func (s *MemorySessionStore) Save(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.ID] = session
	return nil
}

// Get 实现SessionStore接口
func (s *MemorySessionStore) Get(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[id]
	if !ok {
		return nil, NewAuthError("", ErrSessionNotFound, "会话不存在", nil)
	}

	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, id)
		return nil, NewAuthError("", ErrSessionExpired, "会话已过期", nil)
	}

	return session, nil
}

// Delete 实现SessionStore接口
func (s *MemorySessionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, id)
	return nil
}

// Clear 实现SessionStore接口
func (s *MemorySessionStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions = make(map[string]*Session)
	return nil
}

// SessionManager 会话管理器
type SessionManager struct {
	store      SessionStore
	expiration time.Duration
}

// NewSessionManager 创建新的会话管理器
func NewSessionManager(store SessionStore, expiration time.Duration) *SessionManager {
	if store == nil {
		store = NewMemorySessionStore() // 默认使用内存存储
	}
	return &SessionManager{
		store:      store,
		expiration: expiration,
	}
}

// CreateSession 创建新会话
func (m *SessionManager) CreateSession(provider string, token string, userInfo map[string]interface{}) (*Session, error) {
	session := &Session{
		ID:        generateSessionID(),
		Provider:  provider,
		Token:     token,
		UserInfo:  userInfo,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(m.expiration),
		Data:      make(map[string]interface{}),
	}

	if err := m.store.Save(session); err != nil {
		return nil, err
	}

	return session, nil
}

// GetSession 获取会话
func (m *SessionManager) GetSession(id string) (*Session, error) {
	return m.store.Get(id)
}

// DeleteSession 删除会话
func (m *SessionManager) DeleteSession(id string) error {
	return m.store.Delete(id)
}

// ClearSessions 清理所有会话
func (m *SessionManager) ClearSessions() error {
	return m.store.Clear()
}

// generateSessionID 生成会话ID
func generateSessionID() string {
	return uuid.New().String()
}

// MarshalJSON 实现JSON序列化
func (s *Session) MarshalJSON() ([]byte, error) {
	type Alias Session
	return json.Marshal(&struct {
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
		*Alias
	}{
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
		ExpiresAt: s.ExpiresAt.Format(time.RFC3339),
		Alias:     (*Alias)(s),
	})
}

// UnmarshalJSON 实现JSON反序列化
func (s *Session) UnmarshalJSON(data []byte) error {
	type Alias Session
	aux := &struct {
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var err error
	s.CreatedAt, err = time.Parse(time.RFC3339, aux.CreatedAt)
	if err != nil {
		return err
	}

	s.ExpiresAt, err = time.Parse(time.RFC3339, aux.ExpiresAt)
	if err != nil {
		return err
	}

	return nil
}
