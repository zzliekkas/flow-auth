package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/zzliekkas/flow-auth/v3/oauth"
	"github.com/zzliekkas/flow-auth/v3/social"
)

const (
	// 微信OAuth2端点
	wechatAuthURL            = "https://open.weixin.qq.com/connect/qrconnect"        // 开放平台网页授权
	wechatMPAuthURL          = "https://open.weixin.qq.com/connect/oauth2/authorize" // 公众号网页授权
	wechatMiniProgramAuthURL = "https://api.weixin.qq.com/sns/jscode2session"        // 小程序登录
	wechatTokenURL           = "https://api.weixin.qq.com/sns/oauth2/access_token"
	wechatUserURL            = "https://api.weixin.qq.com/sns/userinfo"
	wechatRefreshURL         = "https://api.weixin.qq.com/sns/oauth2/refresh_token"
	wechatMPTokenURL         = "https://api.weixin.qq.com/sns/oauth2/access_token" // 公众号获取token
	wechatMPUserURL          = "https://api.weixin.qq.com/sns/userinfo"            // 公众号获取用户信息
)

// WechatProvider 微信登录提供者
type WechatProvider struct {
	clientID      string // AppID
	clientSecret  string // AppSecret
	redirectURL   string
	scopes        []string
	client        *oauth.OAuth2Client
	isMiniProgram bool // 是否为小程序
	isMP          bool // 是否为公众号
}

// WechatOption 微信提供者选项
type WechatOption func(*WechatProvider)

// WithMiniProgram 设置为小程序模式
func WithMiniProgram() WechatOption {
	return func(p *WechatProvider) {
		p.isMiniProgram = true
	}
}

// WithMP 设置为公众号模式
func WithMP() WechatOption {
	return func(p *WechatProvider) {
		p.isMP = true
	}
}

// NewWechatProvider 创建微信提供者
func NewWechatProvider(clientID, clientSecret, redirectURL string, scopes []string, opts ...WechatOption) *WechatProvider {
	if len(scopes) == 0 {
		scopes = []string{"snsapi_login"}
	}

	provider := &WechatProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
	}

	// 应用选项
	for _, opt := range opts {
		opt(provider)
	}

	// 根据模式选择不同的端点
	authURL := wechatAuthURL
	tokenURL := wechatTokenURL
	if provider.isMP {
		authURL = wechatMPAuthURL
		tokenURL = wechatMPTokenURL
		if len(scopes) == 0 || scopes[0] == "snsapi_login" {
			scopes = []string{"snsapi_userinfo"}
		}
	}

	provider.client = oauth.NewOAuth2Client(&oauth.OAuth2Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	})

	return provider
}

// Name 实现Provider接口
func (p *WechatProvider) Name() string {
	if p.isMiniProgram {
		return "wechat_mini"
	}
	if p.isMP {
		return "wechat_mp"
	}
	return "wechat"
}

// GetOAuth2Config 实现Provider接口
func (p *WechatProvider) GetOAuth2Config() oauth.OAuth2Config {
	return p.client
}

// GetUserInfo 实现Provider接口
func (p *WechatProvider) GetUserInfo(ctx context.Context, token *oauth.Token) (*social.UserInfo, error) {
	// 创建HTTP客户端
	client := p.client.Client(ctx, token)

	// 构建用户信息请求URL
	userURL := wechatUserURL
	if p.isMP {
		userURL = wechatMPUserURL
	}

	// 添加必要的参数
	params := url.Values{}
	params.Set("access_token", token.AccessToken)
	params.Set("openid", token.Raw.(map[string]interface{})["openid"].(string))
	if p.isMP {
		params.Set("lang", "zh_CN")
	}

	// 发送请求
	resp, err := client.Get(userURL + "?" + params.Encode())
	if err != nil {
		return nil, fmt.Errorf("获取微信用户信息失败: %w", err)
	}
	defer resp.Body.Close()

	var wechatUser struct {
		OpenID     string   `json:"openid"`
		UnionID    string   `json:"unionid"`
		Nickname   string   `json:"nickname"`
		Sex        int      `json:"sex"`
		Province   string   `json:"province"`
		City       string   `json:"city"`
		Country    string   `json:"country"`
		HeadImgURL string   `json:"headimgurl"`
		Privilege  []string `json:"privilege"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&wechatUser); err != nil {
		return nil, fmt.Errorf("解析微信用户信息失败: %w", err)
	}

	// 转换为通用用户信息
	userInfo := &social.UserInfo{
		Provider:       p.Name(),
		ProviderUserID: wechatUser.UnionID, // 优先使用UnionID
		Username:       wechatUser.Nickname,
		Nickname:       wechatUser.Nickname,
		Avatar:         wechatUser.HeadImgURL,
		Raw: map[string]interface{}{
			"openid":     wechatUser.OpenID,
			"unionid":    wechatUser.UnionID,
			"nickname":   wechatUser.Nickname,
			"sex":        wechatUser.Sex,
			"province":   wechatUser.Province,
			"city":       wechatUser.City,
			"country":    wechatUser.Country,
			"headimgurl": wechatUser.HeadImgURL,
			"privilege":  wechatUser.Privilege,
		},
	}

	// 如果没有UnionID，则使用OpenID
	if userInfo.ProviderUserID == "" {
		userInfo.ProviderUserID = wechatUser.OpenID
	}

	return userInfo, nil
}

// AuthCodeURL 重写授权URL生成方法，适配微信特殊需求
func (p *WechatProvider) AuthCodeURL(state string, opts ...oauth.AuthCodeOption) string {
	var options struct {
		extraParams url.Values
	}

	// 处理选项
	for _, opt := range opts {
		opt.(interface {
			apply(*struct{ extraParams url.Values })
		}).apply(&options)
	}

	v := url.Values{
		"appid":         {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(p.scopes, ",")},
	}

	if state != "" {
		v.Set("state", state)
	}

	if options.extraParams != nil {
		for key, values := range options.extraParams {
			v[key] = values
		}
	}

	// 根据不同模式使用不同的URL
	baseURL := wechatAuthURL
	if p.isMiniProgram {
		baseURL = wechatMiniProgramAuthURL
	} else if p.isMP {
		baseURL = wechatMPAuthURL
	}

	return baseURL + "?" + v.Encode() + "#wechat_redirect"
}
