package handlers

import (
	"encoding/json"
	"fmt"
	"forum/app/models"
	"forum/pkg"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	GithubTokenURL     = "https://github.com/login/oauth/access_token"
	GithubUserInfoURL  = "https://api.github.com/user" // Исправленный URL
	GithubRedirectURL  = "http://localhost:8000/github/auth/callback"
	GithubClientId     = "Ov23ctIjxi2ooIiJ3Lfl"
	GithubClientSecret = "227a5d378ae6fe6987c8b8d3280d433775676cd5"
)

func (app *App) GithubLoginHandler(w http.ResponseWriter, r *http.Request) {
	scope := url.QueryEscape("user:email")
	authURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=%s",
		GithubClientId, GithubRedirectURL, scope)

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (app *App) GithubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	if code == "" {
		log.Println("Error: empty authorization code")
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}

	resToken, err := getGithubAuthToken(code)
	if err != nil {
		log.Printf("Error getting GitHub auth token: %v\n", err)
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}

	if resToken.AccessToken == "" {
		log.Println("Error: empty access token")
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}

	githubUser, err := getGithubUser(resToken.AccessToken)
	if err != nil {
		log.Printf("Error getting GitHub user: %v\n", err)
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}
	emails, err := getGithubUserEmails(resToken.AccessToken)
	if err != nil {
		log.Printf("Error getting GitHub user emails: %v\n", err)
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}

	var primaryEmail string
	for _, email := range emails {
		if email.Primary && email.Verified {
			primaryEmail = email.Email
			break
		}
	}
	if primaryEmail == "" {
		log.Println("No verified primary email found")
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	}
	githubUser.Email = primaryEmail
	app.SingleSignOn(w, r, githubUser)

}

func getGithubAuthToken(code string) (models.GithubResponse, error) {
	values := url.Values{}

	values.Set("code", code)
	values.Set("client_id", GithubClientId)
	values.Set("client_secret", GithubClientSecret)
	values.Set("redirect_uri", GithubRedirectURL)

	request, err := http.NewRequest("POST", GithubTokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		log.Printf("Error creating request for GitHub token: %v\n", err)
		return models.GithubResponse{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Printf("Error sending request for GitHub token: %v\n", err)
		return models.GithubResponse{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		log.Printf("Error: non-200 response from GitHub token endpoint: %d\n", response.StatusCode)
		return models.GithubResponse{}, fmt.Errorf("non-200 response: %d", response.StatusCode)
	}

	var githubResponse models.GithubResponse
	err = json.NewDecoder(response.Body).Decode(&githubResponse)
	if err != nil {
		log.Printf("Error decoding GitHub token response: %v\n", err)
		return models.GithubResponse{}, err
	}

	return githubResponse, nil
}

func getGithubUser(accessToken string) (models.OAuthUser, error) {
	request, err := http.NewRequest("GET", GithubUserInfoURL, nil)
	if err != nil {
		log.Printf("Error creating request for GitHub user: %v\n", err)
		return models.OAuthUser{}, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Printf("Error sending request for GitHub user: %v\n", err)
		return models.OAuthUser{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		log.Printf("Error: non-200 response from GitHub user endpoint: %d\n", response.StatusCode)
		return models.OAuthUser{}, fmt.Errorf("non-200 response: %d", response.StatusCode)
	}

	var githubUser models.OAuthUser
	err = json.NewDecoder(response.Body).Decode(&githubUser)
	if err != nil {
		log.Printf("Error decoding GitHub user response: %v\n", err)
		return models.OAuthUser{}, err
	}
	return githubUser, nil
}
func getGithubUserEmails(accessToken string) ([]models.GithubEmail, error) {
	request, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		log.Printf("Error creating request for GitHub user emails: %v\n", err)
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Printf("Error sending request for GitHub user emails: %v\n", err)
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		log.Printf("Error: non-200 response from GitHub user emails endpoint: %d\n", response.StatusCode)
		return nil, fmt.Errorf("non-200 response: %d", response.StatusCode)
	}

	var emails []models.GithubEmail
	err = json.NewDecoder(response.Body).Decode(&emails)
	if err != nil {
		log.Printf("Error decoding GitHub user emails response: %v\n", err)
		return nil, err
	}

	return emails, nil
}
