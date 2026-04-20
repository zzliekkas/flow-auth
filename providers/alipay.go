package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/zzliekkas/flow-auth/v3/oauth"
	"github.com/zzliekkas/flow-auth/v3/social"
)

const (
	// 支付宝OAuth2端点
	alipayAuthURL  = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm"
	alipayTokenURL = "https://openapi.alipay.com/gateway.do"
	alipayUserURL  = "https://openapi.alipay.com/gateway.do"
)

// AlipayProvider 支付宝登录提供者
type AlipayProvider struct {
	clientID     string // AppID
	clientSecret string // 应用私钥
	redirectURL  string
	scopes       []string
	client       *oauth.OAuth2Client
	publicKey    string // 支付宝公钥
}

// AlipayOption 支付宝提供者选项
type AlipayOption func(*AlipayProvider)

// WithPublicKey 设置支付宝公钥
func WithPublicKey(publicKey string) AlipayOption {
	return func(p *AlipayProvider) {
		p.publicKey = publicKey
	}
}

// NewAlipayProvider 创建支付宝提供者
func NewAlipayProvider(clientID, clientSecret, redirectURL string, scopes []string, opts ...AlipayOption) *AlipayProvider {
	if len(scopes) == 0 {
		scopes = []string{"auth_user"}
	}

	provider := &AlipayProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
	}

	// 应用选项
	for _, opt := range opts {
		opt(provider)
	}

	provider.client = oauth.NewOAuth2Client(&oauth.OAuth2Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      alipayAuthURL,
		TokenURL:     alipayTokenURL,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	})

	return provider
}

// Name 实现Provider接口
func (p *AlipayProvider) Name() string {
	return "alipay"
}

// GetOAuth2Config 实现Provider接口
func (p *AlipayProvider) GetOAuth2Config() oauth.OAuth2Config {
	return p.client
}

// GetUserInfo 实现Provider接口
func (p *AlipayProvider) GetUserInfo(ctx context.Context, token *oauth.Token) (*social.UserInfo, error) {
	// 构建系统参数
	params := url.Values{}
	params.Set("app_id", p.clientID)
	params.Set("method", "alipay.user.info.share")
	params.Set("format", "JSON")
	params.Set("charset", "utf-8")
	params.Set("sign_type", "RSA2")
	params.Set("timestamp", time.Now().Format("2006-01-02 15:04:05"))
	params.Set("version", "1.0")
	params.Set("auth_token", token.AccessToken)

	// 签名参数
	// TODO: 实现RSA2签名逻辑

	// 发送请求
	client := p.client.Client(ctx, token)
	resp, err := client.PostForm(alipayUserURL, params)
	if err != nil {
		return nil, fmt.Errorf("获取支付宝用户信息失败: %w", err)
	}
	defer resp.Body.Close()

	var response struct {
		AlipayUserInfoShareResponse struct {
			Code               string `json:"code"`
			Msg                string `json:"msg"`
			SubCode            string `json:"sub_code"`
			SubMsg             string `json:"sub_msg"`
			UserID             string `json:"user_id"`
			Avatar             string `json:"avatar"`
			Province           string `json:"province"`
			City               string `json:"city"`
			NickName           string `json:"nick_name"`
			Gender             string `json:"gender"`
			IsStudentCertified string `json:"is_student_certified"`
			UserType           string `json:"user_type"`
			UserStatus         string `json:"user_status"`
			IsCertified        string `json:"is_certified"`
		} `json:"alipay_user_info_share_response"`
		Sign string `json:"sign"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("解析支付宝用户信息失败: %w", err)
	}

	// 验证响应签名
	// TODO: 实现签名验证逻辑

	if response.AlipayUserInfoShareResponse.Code != "10000" {
		return nil, fmt.Errorf("获取支付宝用户信息失败: %s - %s",
			response.AlipayUserInfoShareResponse.SubCode,
			response.AlipayUserInfoShareResponse.SubMsg)
	}

	// 转换为通用用户信息
	userInfo := &social.UserInfo{
		Provider:       p.Name(),
		ProviderUserID: response.AlipayUserInfoShareResponse.UserID,
		Username:       response.AlipayUserInfoShareResponse.NickName,
		Nickname:       response.AlipayUserInfoShareResponse.NickName,
		Avatar:         response.AlipayUserInfoShareResponse.Avatar,
		Raw: map[string]interface{}{
			"user_id":      response.AlipayUserInfoShareResponse.UserID,
			"nick_name":    response.AlipayUserInfoShareResponse.NickName,
			"avatar":       response.AlipayUserInfoShareResponse.Avatar,
			"province":     response.AlipayUserInfoShareResponse.Province,
			"city":         response.AlipayUserInfoShareResponse.City,
			"gender":       response.AlipayUserInfoShareResponse.Gender,
			"user_type":    response.AlipayUserInfoShareResponse.UserType,
			"user_status":  response.AlipayUserInfoShareResponse.UserStatus,
			"is_certified": response.AlipayUserInfoShareResponse.IsCertified,
		},
	}

	return userInfo, nil
}

// AuthCodeURL 重写授权URL生成方法，适配支付宝特殊需求
func (p *AlipayProvider) AuthCodeURL(state string, opts ...oauth.AuthCodeOption) string {
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
		"app_id":       {p.clientID},
		"scope":        {strings.Join(p.scopes, ",")},
		"redirect_uri": {p.redirectURL},
	}

	if state != "" {
		v.Set("state", state)
	}

	if options.extraParams != nil {
		for key, values := range options.extraParams {
			v[key] = values
		}
	}

	return alipayAuthURL + "?" + v.Encode()
}
