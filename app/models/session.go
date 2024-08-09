package models

import "time"

type Session struct {
	ID       int64
	UserID   int64
	Email    string
	Username string
	Token    string
	Expiry   time.Time
}
