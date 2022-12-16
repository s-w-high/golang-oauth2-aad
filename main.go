package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/google/uuid"
)

type TokenEndPointResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type AccessToken struct {
	Scope string `json:"scp"`
}

type Response struct {
	Result string `json:"result"`
}

// 認可前のページ
func handleIndex(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("html/index.html")
	t.Execute(w, nil)
}

// アクセストークン取得後のページ
func handleTop(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("html/top.html")
	t.Execute(w, nil)
}

func handleAuthzStart(w http.ResponseWriter, r *http.Request) {

	tenantId := os.Getenv("AUTH_TENANT_ID")
	clientId := os.Getenv("AUTH_CLIENT_ID")
	scope := os.Getenv("AUTH_SCOPE")
	redirectUri := os.Getenv("AUTH_REDIRECT_URI")

	state, _ := uuid.NewUUID()

	authorizeEndpointUrl := fmt.Sprintf(`https://login.microsoftonline.com/%s/oauth2/v2.0/authorize
		?client_id=%s
		&response_type=code
		&response_mode=query
		&state=%s
		&scope=%s
		&redirect_uri=%s
		`, tenantId, clientId, state, scope, redirectUri)

	// 認可エンドポイントにリダイレクト
	http.Redirect(w, r, authorizeEndpointUrl, http.StatusFound)
}

func handleAuthzCallback(w http.ResponseWriter, r *http.Request) {
	var tokenEndPointResponse TokenEndPointResponse

	tenantId := os.Getenv("AUTH_TENANT_ID")
	clientId := os.Getenv("AUTH_CLIENT_ID")
	clientSecret := os.Getenv("AUTH_CLIENT_SECRET")
	redirectUri := os.Getenv("AUTH_REDIRECT_URI")

	// 認可コードを取得
	authorization_code := r.URL.Query().Get("code")

	// トークンエンドポイントからアクセストークンを取得
	tokenEndPointUrl := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId)
	form := url.Values{}
	form.Add("client_id", clientId)
	form.Add("client_secret", clientSecret)
	form.Add("code", authorization_code)
	form.Add("redirect_uri", redirectUri)
	form.Add("grant_type", "authorization_code")

	body := strings.NewReader(form.Encode())
	req, err := http.NewRequest("POST", tokenEndPointUrl, body)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Restrict-Access-To-Tenants", tenantId)
	client := new(http.Client)
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		dump, _ := httputil.DumpResponse(res, true)
		fmt.Printf("%q", dump)
		return
	}

	resBody, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(resBody, &tokenEndPointResponse); err != nil {
		fmt.Println(err)
		return
	}

	// アクセストークンをCookieに格納
	cookieAccessToken := &http.Cookie{
		Name:  "AUTH_ACCESS_TOKEN",
		Value: tokenEndPointResponse.AccessToken,
		Path:  "/",
	}
	http.SetCookie(w, cookieAccessToken)

	// Topページにリダイレクト
	topEndPointUrl := "/top"
	http.Redirect(w, r, topEndPointUrl, http.StatusFound)
}

// Mail.Readの権限を保持していればOKなエンドポイント
func handleRead(w http.ResponseWriter, r *http.Request) {
	// Authorizationヘッダからアクセストークンを取得
	accessToken := r.Header.Get("Authorization")

	// アクセストークン（JWT）からscp（scope）を取得（処理は割愛）
	scope := decodeJwtPayloadScope(accessToken)

	// 権限にMail.Readが含まれていればOK、含まれていなければNGの文言を返却
	isCall := contains(scope, "Mail.Read")
	var res Response
	if isCall {
		res.Result = "APIコール成功!!!（権限あり）"
	} else {
		res.Result = "APIコール失敗,,,（権限なし）"
	}
	output, _ := json.Marshal(res)
	w.Write(output)
}

func handleReadWrite(w http.ResponseWriter, r *http.Request) {
	// Mail.ReadWriteが権限を保持していればOK（Mail.ReadだけではNG）
	accessToken := r.Header.Get("Authorization")
	scope := decodeJwtPayloadScope(accessToken)

	isCall := contains(scope, "Mail.ReadWrite")

	var res Response
	if isCall {
		res.Result = "APIコール成功!!!（権限あり）"
	} else {
		res.Result = "APIコール失敗,,,（権限なし）"
	}
	output, _ := json.Marshal(res)
	w.Write(output)
}

func contains(s []string, e string) bool {
	for _, v := range s {
		if e == v {
			return true
		}
	}
	return false
}

func decodeJwtPayloadScope(jwt string) []string {
	jwtArray := strings.Split(jwt, ".")
	dec, _ := base64.StdEncoding.DecodeString(jwtArray[1])

	var accessToken AccessToken
	if err := json.Unmarshal([]byte(string(dec)+"}"), &accessToken); err != nil {
		log.Fatal(err)
	}
	arr := strings.Split(accessToken.Scope, " ")

	return arr
}

func main() {

	port := "8080"
	log.Println("webサーバを起動しました。(ポート：" + port + ")")

	// routing
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/top", handleTop)
	http.HandleFunc("/authz-start", handleAuthzStart)
	http.HandleFunc("/authz-callback", handleAuthzCallback)
	http.HandleFunc("/read", handleRead)
	http.HandleFunc("/read-write", handleReadWrite)

	http.ListenAndServe(":"+port, nil)
}
