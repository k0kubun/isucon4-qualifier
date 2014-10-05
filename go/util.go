package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"os"
)

func getEnv(key string, def string) string {
	v := os.Getenv(key)
	if len(v) == 0 {
		return def
	}

	return v
}

func getFlash(c *gin.Context, key string) string {
	session, _ := store.Get(c.Request, "isu4_qualifier")

	if value, ok := session.Values[key]; ok {
		return value.(string)
	} else {
		return ""
	}
}

func calcPassHash(password, hash string) string {
	h := sha256.New()
	io.WriteString(h, password)
	io.WriteString(h, ":")
	io.WriteString(h, hash)

	return fmt.Sprintf("%x", h.Sum(nil))
}
