package models

type Data struct {
	Posts       []Post
	Message     string
	User        User
	Comment     []Comment
	InitialPost Post
	Genre       string
}
