package handlers

import (
	"encoding/json"
	"fmt"
	"forum/app/models"
	"forum/pkg"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	GoogleAuthURL     = "https://accounts.google.com/o/oauth2/auth"
	GoogleUserInfoUrl = "https://www.googleapis.com/oauth2/v2/userinfo"
	GoogleTokenUrl    = "https://accounts.google.com/o/oauth2/token"
	ClientId          = "828677259564-u6libcjtdog4tfcm9c1t4dsipgne0m9i.apps.googleusercontent.com"
	ClientSecret      = "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"
	RedirectURL       = "http://localhost:8000/google/auth/callback"
)

func (app *App) SingleSignOn(w http.ResponseWriter, r *http.Request, googleData models.GoogleUser) {
	// Попробуем найти пользователя в базе данных по Email
	user, err := app.userService.GetUserByEmail(googleData.Email)
	if err != nil {
		fmt.Println("Error fetching user:", err)
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}

	if googleData.Email == "" {
		// Если пользователь не найден, создаем нового пользователя в базе данных
		newUser := models.User{
			Email:    googleData.Email,
			Username: googleData.Name,
		}
		err := app.authService.Register(&newUser)
		if err != nil {
			fmt.Println(err, "REgistter user")
			pkg.ErrorHandler(w, http.StatusInternalServerError)
			return
		}
		user = newUser
	} else {
		// Если пользователь найден, обновляем его данные, если необходимо
		user.Username = googleData.Name
		user.Email = googleData.Email
		// Обновляем данные пользователя в базе данных
		err := app.authService.UpdateUser(&user)
		if err != nil {
			pkg.ErrorHandler(w, http.StatusInternalServerError)
			return
		}
	}
	session := models.Session{
		UserID:   user.ID,
		Email:    user.Email,
		Username: user.Username,
		Token:    uuid.NewString(),
		Expiry:   time.Now().Add(10 * time.Minute),
	}

	err = app.sessionService.CreateSession(&session)
	if err != nil {
		fmt.Println("Error creating session:", err)
		Messages.Message = "Failed to create session"
		http.Redirect(w, r, "/sign-in", http.StatusFound)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   session.Token,
		Expires: session.Expiry,
	})

	Sessions = append(Sessions, session)

	// Перенаправляем пользователя на главную страницу
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *App) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	scope := url.QueryEscape("email profile https://www.googleapis.com/auth/drive.file")
	URL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&prompt=select_account", GoogleAuthURL, ClientId, RedirectURL, scope)
	fmt.Println(URL, "Url")
	fmt.Println(1111)
	http.Redirect(w, r, URL, http.StatusTemporaryRedirect)
}

func (app *App) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	fmt.Println(22222)

	if code == "" {
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}
	resToken, err := getGoogleAuthToken(code)
	if err != nil {
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}
	googleUser, err := getGoogleUser(resToken.AccessToken)
	if err != nil {
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}
	fmt.Println("Google user:", googleUser)

	// Передаем полученные данные в SingleSignOn
	app.SingleSignOn(w, r, googleUser)
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

func getGoogleUser(accessToken string) (models.GoogleUser, error) {

	request, err := http.NewRequest("GET", GoogleUserInfoUrl, nil)
	if err != nil {
		fmt.Println(111)
		return models.GoogleUser{}, err
	}
	request.Header.Add("Authorization", "Bearer "+accessToken)
	client := http.Client{}
	res, err := client.Do(request)
	if err != nil {
		fmt.Println(222)
		return models.GoogleUser{}, err
	}
	defer res.Body.Close()

	var UserResult models.GoogleUser
	fmt.Println(res.Body)
	err = json.NewDecoder(res.Body).Decode(&UserResult)
	if err != nil {
		fmt.Println(333)
		return models.GoogleUser{}, err
	}
	fmt.Println(UserResult.Email, "user email from getGoogleUser")
	return UserResult, nil
}
