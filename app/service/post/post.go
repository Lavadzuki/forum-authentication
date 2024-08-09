package post

import (
	"errors"
	"forum/app/models"
	"log"
	"net/http"
	"strings"
)

func (p postService) GetAllPosts() ([]models.Post, error) {
	posts, err := p.repository.GetAllPosts()
	if err != nil {
		return []models.Post{}, err
	}
	result := []models.Post{}
	for i := len(posts) - 1; i >= 0; i-- {
		result = append(result, posts[i])
	}
	return result, nil
}

func (p postService) CreatePost(post *models.Post) (int, error) {
	ok := validDataString(post.Title)
	if !ok {
		return http.StatusBadRequest, errors.New("title is invalid")
	}

	if !ok {
		return http.StatusBadRequest, errors.New("content is invalid")
	}
	ok = validCategory(post.Category)
	if !ok {
		return http.StatusBadRequest, errors.New("category is invalid")
	}
	id, err := p.repository.CreatePost(*post)
	if err != nil {
		return http.StatusInternalServerError, errors.New("creating a post was failed")
	}
	categories := models.Category{
		CategoryName: post.Category,
		PostId:       id,
	}
	err = p.repository.CreateCategory(&categories)
	if err != nil {
		return http.StatusInternalServerError, errors.New("creating a category was failed")
	}
	return http.StatusOK, nil
}

func (p postService) GetAllCommentsAndPostsByPostId(id int64) (models.Post, int) {
	initialPost, err := p.repository.GetPostById(id)
	if err != nil {
		log.Println(err)
		return models.Post{}, http.StatusBadRequest
	}
	comments, err := p.repository.GetAllCommentByPostId(int(id))
	if err != nil {
		log.Println(2)
		log.Println(err)
		return models.Post{}, http.StatusInternalServerError
	}

	sortedComments := []models.Comment{}

	for i := len(comments) - 1; i >= 0; i-- {
		sortedComments = append(sortedComments, comments[i])
	}
	initialPost.Comment = sortedComments
	return initialPost, http.StatusOK
}

func (p postService) CreateComment(comment *models.Comment) (int, error) {
	ok := validDataString(comment.Message)
	if !ok {
		return http.StatusBadRequest, errors.New("comment message is invalid")
	}
	_, err := p.repository.GetPostById(comment.PostId)
	if err != nil {
		return http.StatusBadRequest, errors.New("post doesnt exists")
	}
	err = p.repository.CommentPost(*comment)
	if err != nil {
		log.Println(err)
		return http.StatusInternalServerError, errors.New("comment post was failed")
	}
	return http.StatusOK, nil
}

func validDataString(s string) bool {
	str := strings.TrimSpace(s)
	if len(str) == 0 {
		return false
	}
	//for _, v := range str {
	//	if v < rune(32) {
	//		return false
	//	}
	//}
	return true
}
