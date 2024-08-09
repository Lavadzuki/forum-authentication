package handlers

import (
	"forum/app/models"
	"forum/pkg"
	"log"
	"net/http"
	"time"
)

func (app *App) PostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		pkg.RenderTemplate(w, "createpost.html", models.Data{})
		return
	case http.MethodPost:
		err := r.ParseForm()
		if err != nil {
			return
		}
		title := r.FormValue("title")
		message := r.FormValue("message")
		genre := r.Form["category"]

		if len(genre) == 0 {
			pkg.ErrorHandler(w, http.StatusBadRequest)
			return
		}
		user, ok := r.Context().Value(KeyUserType(keyUser)).(models.User)
		if !ok {
			pkg.ErrorHandler(w, http.StatusUnauthorized)
			return
		}
		post := models.Post{
			Title:       title,
			Content:     message,
			Category:    models.Stringslice(genre),
			Author:      user,
			CreatedTime: time.Now().Format(time.RFC822),
		}
		status, err := app.postService.CreatePost(&post)
		if err != nil {
			log.Println(err)
			switch status {
			case http.StatusInternalServerError:
				pkg.ErrorHandler(w, http.StatusInternalServerError)
				return
			case http.StatusBadRequest:
				pkg.ErrorHandler(w, http.StatusBadRequest)
				return
			}
		}
		http.Redirect(w, r, "/", http.StatusFound)

	default:
		pkg.ErrorHandler(w, http.StatusMethodNotAllowed)
		return
	}
}
