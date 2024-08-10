package models

type GoogleResponse struct {
	AccessToken string `json:"access_token"`
	TokenID     string `json:"id_token"`
}
