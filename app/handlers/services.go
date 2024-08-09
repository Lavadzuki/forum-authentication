package handlers

import (
	"forum/app/config"
	"forum/app/models"
	"forum/app/service/post"
	"forum/app/service/session"
	"forum/app/service/user/auth"
	"forum/app/service/user/user"
)

var Messages models.Data

type App struct {
	authService    auth.AuthService
	sessionService session.SessionService
	postService    post.PostService
	userService    user.UserService
	cfg            config.Config
}

func NewAppService(
	authService auth.AuthService,
	sessionService session.SessionService,
	postService post.PostService,
	userService user.UserService,
	cfg config.Config,
) App {
	return App{
		authService:    authService,
		sessionService: sessionService,
		postService:    postService,
		userService:    userService,
		cfg:            cfg,
	}
}
