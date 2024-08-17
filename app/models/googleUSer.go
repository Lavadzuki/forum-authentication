package models

import "encoding/json"

type GoogleUser struct {
	Id       json.Number `json:"id"`
	Email    string      `json:"email"`
	Name     string      `json:"name"`
	Password string      `json:"password,omitempty"`
}
