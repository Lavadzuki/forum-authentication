package handlers

import (
	"forum/app/config"
	"net/http"
	"time"
)

func (app *App) Run(cfg config.Http) *http.Server {
	authPaths := []string{
		"/",
		"/reaction",
		"/post/comment/",
		"/filter/",
		"/post/",
		"/logout/",
		"/welcome/",
		"/sign-in",
		"/sign-up",
		"/welcome/filter/",
		"/welcome/comment/",
		"/post/like/",
		"/post/dislike/",
		"/post/comment/like/",
		"/post/comment/dislike/",
	}
	AddAuthPath(authPaths...)

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.authorizedMiddleware(app.HomeHandler))                  // home
	mux.HandleFunc("/post/", app.authorizedMiddleware(app.PostHandler))             // post
	mux.HandleFunc("/post/like/", app.authorizedMiddleware(app.ReactionHandler))    // reaction
	mux.HandleFunc("/post/dislike/", app.authorizedMiddleware(app.ReactionHandler)) // reaction

	mux.HandleFunc("/post/comment/", app.authorizedMiddleware(app.CommentHandler))          // comment
	mux.HandleFunc("/post/comment/like/", app.authorizedMiddleware(app.ReactionHandler))    // reaction
	mux.HandleFunc("/post/comment/dislike/", app.authorizedMiddleware(app.ReactionHandler)) // reaction

	mux.HandleFunc("/filter/", app.authorizedMiddleware(app.FilterHandler)) // filter
	mux.HandleFunc("/logout/", app.authorizedMiddleware(app.LogoutHandler)) // auth

	mux.HandleFunc("/welcome/", app.nonAuthorizedMiddleware(app.WelcomeHandler))                // home
	mux.HandleFunc("/sign-in", app.nonAuthorizedMiddleware(app.LoginHandler))                   // auth
	mux.HandleFunc("/sign-up", app.nonAuthorizedMiddleware(app.RegisterHandler))                // auth
	mux.HandleFunc("/welcome/filter/", app.nonAuthorizedMiddleware(app.WelcomeFilterHandler))   // filter
	mux.HandleFunc("/welcome/comment/", app.nonAuthorizedMiddleware(app.WelcomeCommentHandler)) // comment

	fs := http.FileServer(http.Dir("./templates/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	server := &http.Server{
		Addr:         cfg.Port,
		Handler:      mux,
		ReadTimeout:  time.Second * time.Duration(cfg.ReadTimeout),  // ReadTimeout is the maximum duration for reading the entire request, including the body. A zero or negative value means there will be no timeout.
		WriteTimeout: time.Second * time.Duration(cfg.WriteTimeout), // WriteTimeout is the maximum duration before timing out writes of the response. It is reset whenever a new request's header is read. Like ReadTimeout, it does not let Handlers make decisions on a per-request basis. A zero or negative value means there will be no timeout.
		IdleTimeout:  time.Second * time.Duration(cfg.IdleTimeout),  // IdleTimeout is the maximum amount of time to wait for the next request when keep-alives are enabled. If IdleTimeout is zero, the value of ReadTimeout is used. If both are zero, there is no timeout.
	}
	return server
}
