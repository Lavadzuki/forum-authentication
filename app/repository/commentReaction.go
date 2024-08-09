package repository

func (p postQuery) GetCommentLikeStatus(commentId, userId int) int {
	query := `select status from comment_likes where comment_id=? and user_id=?`
	var likeStatus int
	p.db.QueryRow(query, commentId, userId).Scan(&likeStatus)
	return likeStatus
}

func (p postQuery) LikeComment(commentId, userID, status int) error {
	query := `insert into comment_likes (user_id, comment_id, status) VALUES (?,?,?)`
	_, err := p.db.Exec(query, userID, commentId, status)
	return err
}

func (p postQuery) UpdateCommentLikeDislike(commentId, like, dislike int) error {
	query := `update comments set like=?,dislike=? where comment_id=?`
	_, err := p.db.Exec(query, like, dislike, commentId)
	return err
}

func (p postQuery) DeleteCommentLike(commentId, userId int) error {
	query := `delete from comment_likes where comment_id=? and user_id=?`
	_, err := p.db.Exec(query, commentId, userId)
	return err
}

func (p postQuery) DislikeComment(commentId, userId, status int) error {
	query := `insert into comment_dislikes(user_id, comment_id, status) values (?,?,?)`
	_, err := p.db.Exec(query, userId, commentId, status)
	return err
}

func (p postQuery) DeleteCommentDislike(commentId, userId int) error {
	query := `delete from comment_dislikes where comment_id= ? and user_id=?`
	_, err := p.db.Exec(query, commentId, userId)
	return err
}

func (p postQuery) GetCommentDislikeStatus(commentId, userId int) int {
	query := `select status from comment_dislikes where comment_id=? and user_id=?`
	var dislikeStatus int
	p.db.QueryRow(query, commentId, userId).Scan(&dislikeStatus)
	return dislikeStatus
}
