package handlers

import (
	"forum/app/models"
	"forum/pkg"
	"log"
	"net/http"
	"strings"
)

func (app *App) FilterHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	category := parts[2]

	if r.Method != http.MethodGet {
		pkg.ErrorHandler(w, http.StatusMethodNotAllowed)
		return
	}
	user, ok := r.Context().Value(KeyUserType(keyUser)).(models.User)
	if !ok {
		pkg.ErrorHandler(w, http.StatusUnauthorized)
		return
	}
	data, status := app.postService.GetFilterPosts(category, user)
	switch status {
	case http.StatusInternalServerError:
		log.Println("Errors")
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	case http.StatusBadRequest:
		pkg.ErrorHandler(w, http.StatusBadRequest)
		return
	case http.StatusOK:
		pkg.RenderTemplate(w, "filter.html", data)
	}
}

func (app *App) WelcomeFilterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		pkg.ErrorHandler(w, http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	category := parts[3]
	data, status := app.postService.GetWelcomeFilterPosts(category)
	switch status {
	case http.StatusInternalServerError:
		pkg.ErrorHandler(w, http.StatusInternalServerError)
		return
	case http.StatusBadRequest:
		pkg.ErrorHandler(w, http.StatusBadRequest)
		return
	case http.StatusOK:
		pkg.RenderTemplate(w, "welcome.html", data)
	}
}
