package providers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zzliekkas/flow-auth/oauth"
	"github.com/zzliekkas/flow-auth/social"
)

const (
	// Google OAuth2端点
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleUserURL  = "https://www.googleapis.com/oauth2/v3/userinfo"
)

// GoogleProvider Google登录提供者
type GoogleProvider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
	client       *oauth.OAuth2Client
}

// NewGoogleProvider 创建Google提供者
func NewGoogleProvider(clientID, clientSecret, redirectURL string, scopes []string) *GoogleProvider {
	if len(scopes) == 0 {
		scopes = []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		}
	}

	provider := &GoogleProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
	}

	provider.client = oauth.NewOAuth2Client(&oauth.OAuth2Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      googleAuthURL,
		TokenURL:     googleTokenURL,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	})

	return provider
}

// Name 实现Provider接口
func (p *GoogleProvider) Name() string {
	return "google"
}

// GetOAuth2Config 实现Provider接口
func (p *GoogleProvider) GetOAuth2Config() oauth.OAuth2Config {
	return p.client
}

// GetUserInfo 实现Provider接口
func (p *GoogleProvider) GetUserInfo(ctx context.Context, token *oauth.Token) (*social.UserInfo, error) {
	// 创建HTTP客户端
	client := p.client.Client(ctx, token)

	// 获取用户信息
	resp, err := client.Get(googleUserURL)
	if err != nil {
		return nil, fmt.Errorf("获取Google用户信息失败: %w", err)
	}
	defer resp.Body.Close()

	var googleUser struct {
		Sub           string `json:"sub"`            // 用户ID
		Name          string `json:"name"`           // 全名
		GivenName     string `json:"given_name"`     // 名
		FamilyName    string `json:"family_name"`    // 姓
		Picture       string `json:"picture"`        // 头像URL
		Email         string `json:"email"`          // 邮箱
		EmailVerified bool   `json:"email_verified"` // 邮箱是否验证
		Locale        string `json:"locale"`         // 语言区域
	}

	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return nil, fmt.Errorf("解析Google用户信息失败: %w", err)
	}

	// 转换为通用用户信息
	userInfo := &social.UserInfo{
		Provider:       p.Name(),
		ProviderUserID: googleUser.Sub,
		Username:       googleUser.Email, // 使用邮箱作为用户名
		Nickname:       googleUser.Name,
		Email:          googleUser.Email,
		Avatar:         googleUser.Picture,
		Raw: map[string]interface{}{
			"sub":            googleUser.Sub,
			"name":           googleUser.Name,
			"given_name":     googleUser.GivenName,
			"family_name":    googleUser.FamilyName,
			"picture":        googleUser.Picture,
			"email":          googleUser.Email,
			"email_verified": googleUser.EmailVerified,
			"locale":         googleUser.Locale,
		},
	}

	return userInfo, nil
}
