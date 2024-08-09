package post

import (
	"net/http"
	"strings"

	"forum/app/models"
)

func (p postService) GetFilterPosts(genre string, user models.User) (models.Data, int) {
	ok := validCategoryFilter(genre)
	if !ok {
		return models.Data{}, http.StatusBadRequest
	}

	var posts []models.Post

	switch genre {
	case "liked-post":
		postId, _ := p.repository.GetLikedPostIdByUserId(int(user.ID))
		for _, v := range postId {
			post, err := p.repository.GetPostById(v)
			if err != nil {
				return models.Data{}, http.StatusBadRequest
			}
			posts = append(posts, post)
		}
		data := models.Data{
			Posts: posts,
			User:  user,
			Genre: "liked-post",
		}
		return data, http.StatusOK

	case "created-post":
		allPosts, _ := p.repository.GetAllPosts()
		for _, v := range allPosts {
			if v.Author.ID == user.ID {
				posts = append(posts, v)
			}
		}
		data := models.Data{
			Posts: posts,
			User:  user,
			Genre: "created-post",
		}
		return data, http.StatusOK

	default:
		categories, err := p.repository.GetCategory()
		if err != nil {
			return models.Data{}, http.StatusInternalServerError
		}

		var postIds []int64
		for _, v := range categories {
			for _, categoryName := range v.CategoryName {
				if string(categoryName) == genre {
					postIds = append(postIds, v.PostId)
					break
				}
			}
		}

		for _, v := range postIds {
			post, err := p.repository.GetPostById(v)
			if err != nil {
				return models.Data{}, http.StatusInternalServerError
			}
			posts = append(posts, post)
		}

		data := models.Data{
			Posts: posts,
			User:  user,
			Genre: genre,
		}
		return data, http.StatusOK
	}
}

func (p postService) GetWelcomeFilterPosts(genre string) (models.Data, int) {
	ok := validCategoryWelcome(genre)
	if !ok {
		return models.Data{}, http.StatusInternalServerError
	}

	var postIds []int64
	var posts []models.Post

	categories, err := p.repository.GetCategory()
	if err != nil {
		return models.Data{}, http.StatusInternalServerError
	}

	for _, v := range categories {
		for _, categoryName := range v.CategoryName {
			if string(categoryName) == genre {
				postIds = append(postIds, v.PostId)
				break
			}
		}
	}

	for _, postId := range postIds {
		post, err := p.repository.GetPostById(postId)
		if err != nil {
			return models.Data{}, http.StatusInternalServerError
		}
		posts = append(posts, post)
	}

	data := models.Data{
		Posts: posts,
		Genre: genre,
	}
	return data, http.StatusOK
}

func validCategory(categories []string) bool {
	// Создаем множество допустимых категорий
	validCategories := map[string]struct{}{
		"romance":   {},
		"adventure": {},
		"comedy":    {},
		"drama":     {},
		"fantasy":   {},
	}

	// Проверяем каждую категорию из входного среза
	for _, category := range categories {
		if _, ok := validCategories[category]; !ok {
			return false
		}
	}
	return true
}

func validCategoryWelcome(s string) bool {
	category := make(map[string]struct{})
	valid := []string{
		"romance",
		"adventure",
		"comedy",
		"drama",
		"fantasy",
	}

	for _, v := range valid {
		category[v] = struct{}{}
	}
	str := strings.Split(s, " ")
	for _, v := range str {
		_, ok := category[v]
		if !ok {
			return false
		}
	}
	return true
}

func validCategoryFilter(s string) bool {
	category := make(map[string]struct{})
	valid := []string{
		"romance",
		"adventure",
		"comedy",
		"drama",
		"fantasy",
		"liked-post",
		"created-post",
	}
	for _, v := range valid {
		category[v] = struct{}{}
	}
	if _, ok := category[s]; !ok {
		return false
	}
	return true
}
