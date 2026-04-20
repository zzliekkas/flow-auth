package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/zzliekkas/flow-auth/v3/oauth"
	"github.com/zzliekkas/flow-auth/v3/social"
)

const (
	// GitHub OAuth2端点
	githubAuthURL  = "https://github.com/login/oauth/authorize"
	githubTokenURL = "https://github.com/login/oauth/access_token"
	githubUserURL  = "https://api.github.com/user"
	githubEmailURL = "https://api.github.com/user/emails"
)

// GitHubProvider GitHub登录提供者
type GitHubProvider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
	client       *oauth.OAuth2Client
}

// NewGitHubProvider 创建GitHub提供者
func NewGitHubProvider(clientID, clientSecret, redirectURL string, scopes []string) *GitHubProvider {
	if len(scopes) == 0 {
		scopes = []string{"user:email"}
	}

	provider := &GitHubProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
	}

	provider.client = oauth.NewOAuth2Client(&oauth.OAuth2Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      githubAuthURL,
		TokenURL:     githubTokenURL,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	})

	return provider
}

// Name 实现Provider接口
func (p *GitHubProvider) Name() string {
	return "github"
}

// GetOAuth2Config 实现Provider接口
func (p *GitHubProvider) GetOAuth2Config() oauth.OAuth2Config {
	return p.client
}

// GetUserInfo 实现Provider接口
func (p *GitHubProvider) GetUserInfo(ctx context.Context, token *oauth.Token) (*social.UserInfo, error) {
	// 创建HTTP客户端
	client := p.client.Client(ctx, token)

	// 获取用户信息
	resp, err := client.Get(githubUserURL)
	if err != nil {
		return nil, fmt.Errorf("获取GitHub用户信息失败: %w", err)
	}
	defer resp.Body.Close()

	var githubUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&githubUser); err != nil {
		return nil, fmt.Errorf("解析GitHub用户信息失败: %w", err)
	}

	// 如果没有获取到邮箱，尝试获取主要邮箱
	if githubUser.Email == "" {
		email, err := p.getPrimaryEmail(ctx, client)
		if err == nil {
			githubUser.Email = email
		}
	}

	// 转换为通用用户信息
	userInfo := &social.UserInfo{
		Provider:       p.Name(),
		ProviderUserID: fmt.Sprintf("%d", githubUser.ID),
		Username:       githubUser.Login,
		Nickname:       githubUser.Name,
		Email:          githubUser.Email,
		Avatar:         githubUser.AvatarURL,
		Raw: map[string]interface{}{
			"id":         githubUser.ID,
			"login":      githubUser.Login,
			"name":       githubUser.Name,
			"email":      githubUser.Email,
			"avatar_url": githubUser.AvatarURL,
		},
	}

	return userInfo, nil
}

// getPrimaryEmail 获取用户的主要邮箱
func (p *GitHubProvider) getPrimaryEmail(ctx context.Context, client *http.Client) (string, error) {
	resp, err := client.Get(githubEmailURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	// 查找主要邮箱
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("未找到主要邮箱")
}
