package sign

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

type TimestampSigner struct {
	bst string
}

var secretKey = "django.http.cookies"
var Sep = ":"

func sign(message string, salt string) string {
	salt = salt + "signer"
	bytes := []byte(salt + secretKey + _config.SECRET_KEY)
	sha1Bytes := sha1.Sum(bytes)
	mac := hmac.New(sha1.New, sha1Bytes[0:20])
	mac.Write([]byte(message))
	expectedMac := mac.Sum(nil)
	signature := base64.StdEncoding.EncodeToString(expectedMac)
	return strings.Replace(strings.Replace(strings.TrimRight(signature, "="), "+", "-", -1), "/", "_", -1)
}

func unsign(valueWithSign string, salt string) string {
	sepPos := strings.LastIndexAny(valueWithSign, Sep)
	if sepPos == -1 {
		return ""
	}
	value := valueWithSign[0:sepPos]
	cookieSign := valueWithSign[sepPos+1:]
	if cookieSign == sign(value, salt) {
		return value
	}
	return ""
}

func NewTimestampSigner() *TimestampSigner {
	return &TimestampSigner{bst: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"}
}

func (t *TimestampSigner) ToBase62(val int) string {
	result := ""
	for {
		a := val % 62
		result = string(t.bst[a]) + result
		val = (val - a) / 62

		if val <= 0 {
			break
		}
	}
	return leftPad(result, "0", 4)
}

func (t *TimestampSigner) GetTimeStamp() string {
	location, err := time.LoadLocation("UTC")
	if err == nil {
		unixTime := time.Date(1970, 1, 1, 0, 0, 0, 0, location)
		unixTimestamp := int(time.Now().UTC().Sub(unixTime).Seconds())
		return t.ToBase62(unixTimestamp)
	}
	return err.Error()
}

func (t *TimestampSigner) Sign(cookie *http.Cookie, salt string) {
	value := cookie.Value + Sep + t.GetTimeStamp()
	salt = cookie.Name + salt
	value = value + Sep + sign(value, salt)
	cookie.Value = "" + value + ""
}

func (t *TimestampSigner) Unsign(cookie *http.Cookie, salt string) string {
	if cookie == nil {
		return ""
	}
	salt = cookie.Name + salt
	value := unsign(strings.Trim(cookie.Value, "\""), salt)
	sepPos := strings.LastIndex(value, Sep)
	if sepPos == -1 {
		return ""
	}
	return value[0:sepPos]
}

func SetSignedCookie(reponse http.ResponseWriter, cookie *http.Cookie, salt string) {
	t := NewTimestampSigner()
	t.Sign(cookie, salt)
	http.SetCookie(reponse, cookie)
}

func GetSignedCookie(request *http.Request, name string, salt string) string {
	cookie, err := request.Cookie(name)
	if err == nil {
		t := NewTimestampSigner()
		return t.Unsign(cookie, salt)
	}
	return ""
}

func leftPad(s string, padStr string, pLen int) string {
	count := pLen - len(s)
	if count <= 0 {
		return s
	}
	return strings.Repeat(padStr, count) + s
}
