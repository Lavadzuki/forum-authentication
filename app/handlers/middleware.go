package handlers

import (
	"context"
	"forum/pkg"
	"net/http"
	"strings"
	"time"
)

var AuthPaths = make(map[string]struct{})

type KeyUserType string

const keyUser = "user"

func AddAuthPath(paths ...string) {
	for _, path := range paths {
		AuthPaths[path] = struct{}{}
	}
	// fmt.Println(AuthPaths)
}

func (app *App) authorizedMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Path
		path := ""
		parts := strings.Split(url, "/")

		if len(parts) == 2 && url != "/" {
			pkg.ErrorHandler(w, http.StatusNotFound)
			return
		}

		if url == "/" {
			path = "/"
		} else if url == "/post/" {
			path = "/post/"
		} else if parts[1] == "filter" {
			path = "/filter/"
		} else if parts[1] == "logout" {
			path = "/logout/"
		} else if parts[2] == "like" {
			path = "/post/like/"
		} else if parts[2] == "dislike" {
			path = "/post/dislike/"
		} else if parts[2] == "comment" && parts[3] == "like" {
			path = "/post/comment/like/"
		} else if parts[2] == "comment" && parts[3] == "dislike" {
			path = "/post/comment/dislike/"
		} else {
			path = "/" + parts[1] + "/" + parts[2] + "/"
			if len(parts) < 4 {
				pkg.ErrorHandler(w, http.StatusNotFound)
				return
			}
		}
		// fmt.Println("AuthPath[path]: ", AuthPaths)
		if _, ok := AuthPaths[path]; !ok {
			pkg.ErrorHandler(w, http.StatusNotFound)
			return
		}
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/sign-in", http.StatusFound)
			return
		}

		session, err := app.sessionService.GetSessionByToken(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/sign-in", http.StatusFound)
			return
		}
		if session.Expiry.Before(time.Now()) {
			http.Redirect(w, r, "/sign-in", http.StatusFound)
			return
		}

		user, err := app.userService.GetUserByToken(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/sign-in", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), KeyUserType(keyUser), user)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (app *App) nonAuthorizedMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// fmt.Println(path)
		parts := strings.Split(r.URL.Path, "/")
		if path == "/sign-in" {
			path = "/sign-in"
		} else if path == "/sign-up" {
			path = "/sign-up"
		} else if path == "/welcome/" {
			path = "/welcome/"
		} else {
			path = "/" + parts[1] + "/" + parts[2] + "/"
		}
		// fmt.Println("path", path)

		if _, ok := AuthPaths[path]; !ok {
			pkg.ErrorHandler(w, http.StatusNotFound)
			return
		}
		cookie, err := r.Cookie("session_token")
		if err != nil {

			next.ServeHTTP(w, r)
			return
		}
		checkSessionFromDb, err := app.sessionService.GetSessionByToken(cookie.Value)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		if checkSessionFromDb.Expiry.Before(time.Now()) {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
}
