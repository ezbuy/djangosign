package sign

import (
	http "net/http"
	"net/http/httptest"
	"testing"
)

func init() {
	Setup(&Config{SECRET_KEY: "b#qdkk5pwax+=(5t8s$q=^t&nn@uu@oshz=b^(q9%)((dul#ds"})
}

func TestSignedCookie(t *testing.T) {
	sign := "F47F3628C36F3F28,DPS"
	salt := ""
	internalTestSignedCookie(t, sign, salt)
}

func TestSignCooikeWithSalt(t *testing.T) {
	sign := "F47F3628C36F3F28,Web"
	salt := "pretty"
	internalTestSignedCookie(t, sign, salt)
}

func internalTestSignedCookie(t *testing.T, sign string, salt string) {
	cookie := http.Cookie{
		Name:  "65_customer",
		Value: sign,
	}
	reponse := httptest.NewRecorder()
	SetSignedCookie(reponse, &cookie, salt)

	req, _ := http.NewRequest("GET", "sg.65emall.net", nil)
	req.AddCookie(&cookie)

	decryptSign := GetSignedCookie(req, "65_customer", salt)

	if sign != decryptSign {
		t.Error("sign = ", sign)
		t.Error("decryptSign = ", decryptSign)
		t.Error("salt = ", salt)
	}
}
