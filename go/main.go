package main

import (
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"strconv"
	"runtime"
)

var db *sql.DB
var logger *Logger
var store = sessions.NewCookieStore([]byte("secret-isucon"))
var (
	UserLockThreshold int
	IPBanThreshold    int
)

func init() {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=Local",
		getEnv("ISU4_DB_USER", "root"),
		getEnv("ISU4_DB_PASSWORD", ""),
		getEnv("ISU4_DB_HOST", "localhost"),
		getEnv("ISU4_DB_PORT", "3306"),
		getEnv("ISU4_DB_NAME", "isu4_qualifier"),
	)

	var err error

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}

	UserLockThreshold, err = strconv.Atoi(getEnv("ISU4_USER_LOCK_THRESHOLD", "3"))
	if err != nil {
		panic(err)
	}

	IPBanThreshold, err = strconv.Atoi(getEnv("ISU4_IP_BAN_THRESHOLD", "10"))
	if err != nil {
		panic(err)
	}

	logger = NewLogger()
}

func getIndex(c *gin.Context) {
	c.HTML(200, "index.tmpl", gin.H{"Flash": getFlash(c, "notice")})
}

func loadLoginLog(c *gin.Context) {
	logger.LoadLoginLog()
	c.String(200, "done")
}

func getMypage(c *gin.Context) {
	var currentUser *User

	session, _ := store.Get(c.Request, "isu4_qualifier")
	if userId, ok := session.Values["user_id"]; ok {
		currentUser = getCurrentUser(userId)
	} else {
		currentUser = nil
	}

	if currentUser == nil {
		c.Redirect(301, "/?err=invalid")
		return
	}

	currentUser.getLastLogin()
	c.HTML(200, "mypage.tmpl", currentUser)
}

func getReport(c *gin.Context) {
	logger.FlushLoginLog()
	c.JSON(200, map[string][]string{
		"banned_ips":   bannedIPs(),
		"locked_users": lockedUsers(),
	})
}

func postLogin(c *gin.Context) {
	user, err := attemptLogin(c.Request)

	if err != nil || user == nil {
		switch err {
		case ErrBannedIP:
			c.Redirect(302, "/?err=banned")
		case ErrLockedUser:
			c.Redirect(302, "/?err=locked")
		default:
			c.Redirect(302, "/?err=wrong")
		}

		return
	}

	session, _ := store.Get(c.Request, "isu4_qualifier")
	session.Values["user_id"] = strconv.Itoa(user.ID)
	session.Save(c.Request, c.Writer)

	c.Redirect(302, "/mypage")
}

func main() {
	runtime.GOMAXPROCS(4)

	r := gin.Default()
	r.LoadHTMLTemplates("./*")

	r.GET("/", getIndex)
	r.GET("/init", loadLoginLog)
	r.GET("/mypage", getMypage)
	r.GET("/report", getReport)
	r.POST("/login", postLogin)

	r.Run(":8080")
}
