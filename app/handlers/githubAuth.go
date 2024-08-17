package handlers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
)

const (
	GithubClientID     = "Ov23ctIjxi2ooIiJ3Lfl"
	GithubClientSecret = "cf5d01f67a9ba5cecb67edf8a4572f9e58492384"
	GithubRedirectURL  = "http://localhost:8000/github/auth/callback"
	GithubAuthURL      = "https://github.com/login/oauth/authorize?scope=user:email&client_id="
	GithubTokenURL     = "https://github.com/login/oauth/access_token"
	GithubUserURL      = "https://api.github.com/user"
)

func (app *App) GithubLogin(w http.ResponseWriter, r *http.Request) {
	URL := GithubAuthURL + GithubClientID + "&redirect_uri=" + GithubRedirectURL
	http.Redirect(w, r, URL, http.StatusTemporaryRedirect)

}

func (app *App) GithubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if len(code) == 0 {
		http.Error(w, "no code in the callback URL", http.StatusBadRequest)
		return
	}
	data := url.Values{}
	data.Set("client_id", GithubClientID)
	data.Set("client_secret", GithubClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", GithubRedirectURL)

	req, err := http.NewRequest("POST", GithubTokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		http.Error(w, "failed creating request", http.StatusBadRequest)
		return
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "failed sending request", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed reading response body", http.StatusBadRequest)
		return
	}
	var accessTokenResponse struct {
		access_token string `json:"access_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}
	err = json.Unmarshal(body, &accessTokenResponse)
	if err != nil {
		http.Error(w, "failed parsing response body", http.StatusBadRequest)
		return
	}
	req, err = http.NewRequest("get", GithubUserURL, nil)
	if err != nil {
		http.Error(w, "failed creating request", http.StatusBadRequest)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessTokenResponse.access_token)

	resp, err = client.Do(req)
	if err != nil {
		http.Error(w, "failed sending request", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed reading response body", http.StatusBadRequest)
		return
	}

	var user struct {
		Login string `json:"login"`
		Email string `json:"email"`
		Name  string `json:"name"`
		ID    string `json:"id"`
	}
	err = json.Unmarshal(body, &user)
	if err != nil {
		http.Error(w, "failed parsing response body", http.StatusBadRequest)
		return
	}

}
