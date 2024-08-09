package models

type Comment struct {
	Id       int64
	PostId   int64
	UserId   int64
	Username string
	Message  string
	Like     int
	Dislike  int
	Born     string
}
