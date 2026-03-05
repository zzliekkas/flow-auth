package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/url"
	"sort"
	"strings"
)

// RSASigner RSA签名器
type RSASigner struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewRSASigner 创建RSA签名器
func NewRSASigner(privateKeyPEM, publicKeyPEM string) (*RSASigner, error) {
	signer := &RSASigner{}

	// 解析私钥
	if privateKeyPEM != "" {
		block, _ := pem.Decode([]byte(privateKeyPEM))
		if block == nil {
			return nil, errors.New("无效的私钥格式")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer.privateKey = privateKey
	}

	// 解析公钥
	if publicKeyPEM != "" {
		block, _ := pem.Decode([]byte(publicKeyPEM))
		if block == nil {
			return nil, errors.New("无效的公钥格式")
		}

		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("不是有效的RSA公钥")
		}
		signer.publicKey = rsaPublicKey
	}

	return signer, nil
}

// Sign 使用RSA2算法对数据进行签名
func (s *RSASigner) Sign(params map[string]string) (string, error) {
	if s.privateKey == nil {
		return "", errors.New("未设置私钥")
	}

	// 将参数按照键名ASCII码升序排序
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 构建待签名字符串
	var signStrings []string
	for _, k := range keys {
		if v := params[k]; v != "" {
			signStrings = append(signStrings, k+"="+v)
		}
	}
	signContent := strings.Join(signStrings, "&")

	// 计算SHA256哈希
	h := sha256.New()
	h.Write([]byte(signContent))
	hash := h.Sum(nil)

	// RSA签名
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hash)
	if err != nil {
		return "", err
	}

	// Base64编码
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify 验证RSA2签名
func (s *RSASigner) Verify(params map[string]string, sign string) error {
	if s.publicKey == nil {
		return errors.New("未设置公钥")
	}

	// 解码签名
	signature, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	// 构建待验证的字符串（与签名时相同的逻辑）
	var keys []string
	for k := range params {
		if k != "sign" && k != "sign_type" { // 排除签名相关字段
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var signStrings []string
	for _, k := range keys {
		if v := params[k]; v != "" {
			signStrings = append(signStrings, k+"="+v)
		}
	}
	signContent := strings.Join(signStrings, "&")

	// 计算SHA256哈希
	h := sha256.New()
	h.Write([]byte(signContent))
	hash := h.Sum(nil)

	// 验证签名
	return rsa.VerifyPKCS1v15(s.publicKey, crypto.SHA256, hash, signature)
}

// SignParams 对URL参数进行签名
func (s *RSASigner) SignParams(params url.Values) (string, error) {
	// 转换url.Values为map[string]string
	paramMap := make(map[string]string)
	for k, v := range params {
		if len(v) > 0 {
			paramMap[k] = v[0]
		}
	}
	return s.Sign(paramMap)
}

// VerifyParams 验证URL参数的签名
func (s *RSASigner) VerifyParams(params url.Values, sign string) error {
	// 转换url.Values为map[string]string
	paramMap := make(map[string]string)
	for k, v := range params {
		if len(v) > 0 {
			paramMap[k] = v[0]
		}
	}
	return s.Verify(paramMap, sign)
}
