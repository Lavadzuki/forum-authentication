package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"forum/app/models"
	"forum/pkg"
	"github.com/google/uuid"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	GoogleAuthURL = "https://accounts.google.com/o/oauth2/auth"

	GoogleUserInfoUrl = "https://www.googleapis.com/oauth2/v2/userinfo"
	GoogleTokenUrl    = "https://accounts.google.com/o/oauth2/token"
	ClientId          = "828677259564-u6libcjtdog4tfcm9c1t4dsipgne0m9i.apps.googleusercontent.com"
	ClientSecret      = "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"
	RedirectURL       = "http://localhost:8000/google/auth/callback"
)

func (app *App) SingleSignOn(w http.ResponseWriter, r *http.Request, googleData models.GoogleUser) {
	// Попробуем найти пользователя в базе данных по Email.
	user, err := app.userService.GetUserByEmail(googleData.Email)
	if err != nil {
		if !errors.Is(sql.ErrNoRows, err) {
			fmt.Println(222)
			pkg.ErrorHandler(w, http.StatusInternalServerError)
			return
		} else {
			fmt.Println(33)
			newUser := models.User{
				Email:    googleData.Email,
				Username: googleData.Name,
			}
			fmt.Println(4)
			err := app.authService.Register(&newUser)
			if err != nil {
				fmt.Println(err, "REgistter user")
				pkg.ErrorHandler(w, http.StatusInternalServerError)
				return
			}
			user, err = app.userService.GetUserByEmail(newUser.Email)
			if err != nil {
				log.Println(err)
				pkg.ErrorHandler(w, http.StatusInternalServerError)
				return
			}
		}
	}

	//} else {
	//	user := models.User{Email: googleData.Email, Username: user.Username}
	//	// Обновляем данные пользователя в базе данных
	//	err := app.authService.UpdateUser(&user)
	//	if err != nil {
	//		pkg.ErrorHandler(w, http.StatusInternalServerError)
	//		return
	//	}
	//}

	session := models.Session{
		UserID:   user.ID,
		Email:    user.Email,
		Username: user.Username,
		Token:    uuid.NewString(),
		Expiry:   time.Now().Add(10 * time.Minute),
	}
	fmt.Println(session)

	err = app.sessionService.CreateSession(&session)
	if err != nil {
		log.Printf("Error creating session: %v", err)
		Messages.Message = "Failed to create session"
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   session.Token,
		Expires: session.Expiry,
	})

	Sessions = append(Sessions, session)

	http.Redirect(w, r, "/", http.StatusFound)
}

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
		log.Printf("Error getting user info: %v", err)
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}

	googleData := models.GoogleUser{
		Email:    googleUser.Email,
		Name:     googleUser.Name,
		Password: googleUser.Password,
	}

	//session, err := app.authService.GoogleAuth(googleData)
	//if err != nil {
	//
	//	pkg.ErrorHandler(w, http.StatusInternalServerError)
	//	return
	//} else {
	//	cookie := http.Cookie{
	//		Name:    "session_token",
	//		Value:   session.Token,
	//		Path:    "/",
	//		Expires: session.Expiry,
	//	}
	//	http.SetCookie(w, &cookie)
	//}
	app.SingleSignOn(w, r, googleData)
	//http.Redirect(w, r, "/", http.StatusSeeOther)
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

func getGoogleUser(accessToken, tokenId string) (models.GoogleUser, error) {
	request, err := http.NewRequest("GET", GoogleUserInfoUrl, nil)
	if err != nil {
		return models.GoogleUser{}, err
	}
	request.Header.Add("Authorization", "Bearer "+accessToken)
	client := http.Client{}
	res, err := client.Do(request)
	if err != nil {
		return models.GoogleUser{}, err
	}
	defer res.Body.Close()
	fmt.Println(res.Body)

	var UserResult models.GoogleUser
	err = json.NewDecoder(res.Body).Decode(&UserResult)
	if err != nil {
		return models.GoogleUser{}, err
	}
	fmt.Println(UserResult.Email, "getgoogleUser")
	return UserResult, nil
}
