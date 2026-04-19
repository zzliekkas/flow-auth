package auth

import (
	"github.com/zzliekkas/flow/v3"
)

// AuthModule implements flow.Module for easy registration into a Flow engine.
type AuthModule struct {
	manager *Manager
}

// NewModule creates a new AuthModule with the given Manager.
func NewModule(manager *Manager) *AuthModule {
	return &AuthModule{manager: manager}
}

// Name returns the module name.
func (m *AuthModule) Name() string {
	return "auth"
}

// Init registers auth services into Flow's DI container.
func (m *AuthModule) Init(e *flow.Engine) error {
	if m.manager != nil {
		if err := e.Provide(func() *Manager { return m.manager }); err != nil {
			return err
		}
	}
	return nil
}
