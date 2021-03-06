package model

import (
	"time"
)

type User struct {
	ID          int
	ChatID      int64
	Alias       string
	Email       string
	Phone       int
	Passw        string
	FirstName  string
	LastName   string
	Active      bool
	Role        int
	Salt        string
	Session_key string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}