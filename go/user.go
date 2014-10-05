package main

import (
	"time"
)

type User struct {
	ID           int
	Login        string
	PasswordHash string
	Salt         string

	LastLogin *LastLogin
}

type LastLogin struct {
	Login     string
	IP        string
	CreatedAt time.Time
}

func (u *User) getLastLogin() *LastLogin {
	u.LastLogin = logger.lastLoginOfUserId(u.ID)
	return u.LastLogin
}
