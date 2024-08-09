package handlers

import (
	"forum/app/models"
	"forum/pkg"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func (app *App) ReactionHandler(w http.ResponseWriter, r *http.Request) {
	path := ""
	ID := 0
	commentID := 0
	isMainPage := r.FormValue("isMainPage")
	category := r.FormValue("FILTER")
	if r.Method != http.MethodPost {
		pkg.ErrorHandler(w, http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if parts[2] == "like" || parts[2] == "dislike" {
		id, err := strconv.Atoi(parts[3])
		if err != nil {
			log.Println(err)
			pkg.ErrorHandler(w, http.StatusInternalServerError)
			return
		}
		ID = id
		path = "/" + parts[1] + "/" + parts[2]
	} else if parts[3] == "like" || parts[3] == "dislike" {
		id, err := strconv.Atoi(parts[4])
		if err != nil {
			log.Println(err)
			pkg.ErrorHandler(w, http.StatusInternalServerError)
			return
		}
		ID = id
		path = "/" + parts[1] + "/" + parts[2] + "/" + parts[3]

		commentiD, err := strconv.Atoi(parts[5])
		if err != nil {
			log.Println(err)
			pkg.ErrorHandler(w, http.StatusInternalServerError)
			return
		}
		commentID = commentiD
	}
	user, ok := r.Context().Value(KeyUserType(keyUser)).(models.User)
	if !ok {
		pkg.ErrorHandler(w, http.StatusUnauthorized)
		return
	}

	// fmt.Println("Switch", path)

	switch path {
	case "/post/like":
		status := app.postService.LikePost(ID, int(user.ID))
		switch status {
		case http.StatusInternalServerError:
			pkg.ErrorHandler(w, http.StatusInternalServerError)
			return
		case http.StatusBadRequest:
			pkg.ErrorHandler(w, http.StatusBadRequest)
			return
		case http.StatusOK:

			switch category {
			case "liked-post":
				http.Redirect(w, r, "/filter/liked-post/", http.StatusFound)
			case "created-post":
				http.Redirect(w, r, "/filter/created-post/", http.StatusFound)
			case "romance":
				http.Redirect(w, r, "/filter/romance/", http.StatusFound)
			case "adventure":
				http.Redirect(w, r, "/filter/adventure/", http.StatusFound)
			case "comedy":
				http.Redirect(w, r, "/filter/comedy/", http.StatusFound)
			case "drama":
				http.Redirect(w, r, "/filter/drama/", http.StatusFound)
			case "fantasy":
				http.Redirect(w, r, "/filter/fantasy/", http.StatusFound)
			default:
				if isMainPage == "true" {
					http.Redirect(w, r, "/", http.StatusFound)
				} else {
					http.Redirect(w, r, "/post/comment/"+strconv.Itoa(ID), http.StatusFound)
				}
			}

		}
	case "/post/dislike":
		status := app.postService.DislikePost(ID, int(user.ID))
		switch status {
		case http.StatusInternalServerError:
			pkg.ErrorHandler(w, http.StatusInternalServerError)
			return
		case http.StatusBadRequest:
			pkg.ErrorHandler(w, http.StatusBadRequest)
			return
		case http.StatusOK:
			switch category {
			case "liked-post":
				http.Redirect(w, r, "/filter/liked-post/", http.StatusFound)
			case "created-post":
				http.Redirect(w, r, "/filter/created-post/", http.StatusFound)
			case "romance":
				http.Redirect(w, r, "/filter/romance/", http.StatusFound)
			case "adventure":
				http.Redirect(w, r, "/filter/adventure/", http.StatusFound)
			case "comedy":
				http.Redirect(w, r, "/filter/comedy/", http.StatusFound)
			case "drama":
				http.Redirect(w, r, "/filter/drama/", http.StatusFound)
			case "fantasy":
				http.Redirect(w, r, "/filter/fantasy/", http.StatusFound)
			default:
				if isMainPage == "true" {
					http.Redirect(w, r, "/", http.StatusFound)
				} else {
					http.Redirect(w, r, "/post/comment/"+strconv.Itoa(ID), http.StatusFound)
				}
			}

		}
	case "/post/comment/like":
		status := app.postService.LikeComment(commentID, int(user.ID))
		switch status {
		case http.StatusInternalServerError:
			pkg.ErrorHandler(w, http.StatusInternalServerError)
			return
		case http.StatusBadRequest:
			pkg.ErrorHandler(w, http.StatusBadRequest)
			return
		case http.StatusOK:
			http.Redirect(w, r, "/post/comment/"+strconv.Itoa(ID), http.StatusFound)
		}
	case "/post/comment/dislike":
		status := app.postService.DislikeComment(commentID, int(user.ID))
		switch status {
		case http.StatusInternalServerError:
			pkg.ErrorHandler(w, http.StatusInternalServerError)
			return
		case http.StatusBadRequest:
			pkg.ErrorHandler(w, http.StatusBadRequest)
			return
		case http.StatusOK:
			http.Redirect(w, r, "/post/comment/"+strconv.Itoa(ID), http.StatusFound)
		}

	default:
		pkg.ErrorHandler(w, http.StatusNotFound)
	}
}
