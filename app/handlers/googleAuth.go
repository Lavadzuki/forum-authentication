package handlers

import (
	"encoding/json"
	"fmt"
	"forum/app/models"
	"forum/pkg"
	"net/http"
	"net/url"
	"strings"
)

const (
	GoogleAuthURL     = "https://accounts.google.com/o/oauth2/auth"
	AccessToken       = "Client"
	GoogleUserInfoUrl = "https://www.googleapis.com/oauth2/v2/userinfo"
	GoogleTokenUrl    = "https://accounts.google.com/o/oauth2/token"
	ClientId          = "828677259564-u6libcjtdog4tfcm9c1t4dsipgne0m9i.apps.googleusercontent.com"
	ClientSecret      = "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"
	RedirectURL       = "http://localhost:8000/google/auth/callback"
)

func (app *App) GoogleLogin(w http.ResponseWriter, r *http.Request) {

	scope := url.QueryEscape("email profile https://www.googleapis.com/auth/drive.file")
	URL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&prompt=select_account", GoogleAuthURL, ClientId, RedirectURL, scope)

	http.Redirect(w, r, URL, http.StatusTemporaryRedirect)
}

func (app *App) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")

	if code == "" {
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}
	resToken, err := getGoogleAuthToken(code)
	if err != nil {
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}
	googleUser, err := getGoogleUser(resToken.AccessToken, resToken.TokenID)
	if err != nil {
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}
	googleData := models.GoogleUser{
		Id:       googleUser.ID,
		Email:    googleUser.Email,
		Name:     googleUser.Username,
		Password: googleUser.Password,
	}
	session, err := app.authService.GoogleAuth(googleData)
	if err != nil {
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	} else {
		cookie := http.Cookie{
			Name:    "session_token",
			Value:   session.Token,
			Path:    "/",
			Expires: session.Expiry,
		}
		http.SetCookie(w, &cookie)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getGoogleAuthToken(authCode string) (models.GoogleResponse, error) {
	values := url.Values{}
	values.Set("code", authCode)
	values.Set("client_id", ClientId)
	values.Set("client_secret", ClientSecret)
	values.Set("redirect_uri", RedirectURL)
	values.Set("grant_type", "authorization_code")

	response, err := http.Post(GoogleTokenUrl, "application/x-www-form-urlencoded", strings.NewReader(values.Encode()))
	if err != nil {
		return models.GoogleResponse{}, err
	}
	defer response.Body.Close()
	var resultToken models.GoogleResponse

	err = json.NewDecoder(response.Body).Decode(&resultToken)
	if err != nil {
		return models.GoogleResponse{}, err
	}
	return resultToken, nil
}

func getGoogleUser(accessToken, tokenId string) (models.User, error) {
	request, err := http.NewRequest("GET", GoogleUserInfoUrl, nil)
	if err != nil {
		return models.User{}, err
	}
	request.Header.Add("Authorization", "Bearer "+AccessToken)
	client := http.Client{}
	res, err := client.Do(request)
	if err != nil {
		return models.User{}, err
	}
	defer res.Body.Close()
	var UserResult models.User
	err = json.NewDecoder(res.Body).Decode(&UserResult)
	if err != nil {
		return models.User{}, err
	}
	return UserResult, nil
}
