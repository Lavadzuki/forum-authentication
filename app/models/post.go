package models

type Post struct {
	Id          int64
	Title       string
	Content     string
	Category    Stringslice
	Comment     []Comment
	Author      User
	Like        int64
	Dislike     int64
	CreatedTime string
}
