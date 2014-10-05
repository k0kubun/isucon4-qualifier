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
var storage *Storage
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

	storage = NewStorage()
}

func getIndex(c *gin.Context) {
	query := c.Request.URL.Query()
	param := query.Get("err")

	if param == "banned" {
		c.Data(200, "text/html", []byte(`
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <script id="css">
    document.write('<link rel="stylesheet" href="/stylesheets/bootstrap.min.css"> <link rel="stylesheet" href="/stylesheets/bootflat.min.css"> <link rel="stylesheet" href="/stylesheets/isucon-bank.css">');
    script = document.getElementById('css');
    script.parentNode.removeChild(script);
    </script>
    <title>isucon4</title>
  </head>
  <body>
    <div class="container">
      <h1 id="topbar">
        <a href="/">
          <script id="img">
          document.write('<img src="/images/isucon-bank.png" alt="いすこん銀行 オンラインバンキングサービス">');
          script = document.getElementById('img');
          script.parentNode.removeChild(script);
          </script>
        </a>
      </h1>
      <div id="be-careful-phising" class="panel panel-danger">
  <div class="panel-heading">
    <span class="hikaru-mozi">偽画面にご注意ください！</span>
  </div>
  <div class="panel-body">
    <p>偽のログイン画面を表示しお客様の情報を盗み取ろうとする犯罪が多発しています。</p>
    <p>ログイン直後にダウンロード中や、見知らぬウィンドウが開いた場合、<br>すでにウィルスに感染している場合がございます。即座に取引を中止してください。</p>
    <p>また、残高照会のみなど、必要のない場面で乱数表の入力を求められても、<br>絶対に入力しないでください。</p>
  </div>
</div>

<div class="page-header">
  <h1>ログイン</h1>
</div>

  <div id="notice-message" class="alert alert-danger" role="alert">You're banned.</div>

<div class="container">
  <form class="form-horizontal" role="form" action="/login" method="POST">
    <div class="form-group">
      <label for="input-username" class="col-sm-3 control-label">お客様ご契約ID</label>
      <div class="col-sm-9">
        <input id="input-username" type="text" class="form-control" placeholder="半角英数字" name="login">
      </div>
    </div>
    <div class="form-group">
      <label for="input-password" class="col-sm-3 control-label">パスワード</label>
      <div class="col-sm-9">
        <input type="password" class="form-control" id="input-password" name="password" placeholder="半角英数字・記号（２文字以上）">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-primary btn-lg btn-block">ログイン</button>
      </div>
    </div>
  </form>
</div>

    </div>

  </body>
</html>
		`))
	} else if param == "wrong" {
		c.Data(200, "text/html", []byte(`
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <script id="css">
    document.write('<link rel="stylesheet" href="/stylesheets/bootstrap.min.css"> <link rel="stylesheet" href="/stylesheets/bootflat.min.css"> <link rel="stylesheet" href="/stylesheets/isucon-bank.css">');
    script = document.getElementById('css');
    script.parentNode.removeChild(script);
    </script>
    <title>isucon4</title>
  </head>
  <body>
    <div class="container">
      <h1 id="topbar">
        <a href="/">
          <script id="img">
          document.write('<img src="/images/isucon-bank.png" alt="いすこん銀行 オンラインバンキングサービス">');
          script = document.getElementById('img');
          script.parentNode.removeChild(script);
          </script>
        </a>
      </h1>
      <div id="be-careful-phising" class="panel panel-danger">
  <div class="panel-heading">
    <span class="hikaru-mozi">偽画面にご注意ください！</span>
  </div>
  <div class="panel-body">
    <p>偽のログイン画面を表示しお客様の情報を盗み取ろうとする犯罪が多発しています。</p>
    <p>ログイン直後にダウンロード中や、見知らぬウィンドウが開いた場合、<br>すでにウィルスに感染している場合がございます。即座に取引を中止してください。</p>
    <p>また、残高照会のみなど、必要のない場面で乱数表の入力を求められても、<br>絶対に入力しないでください。</p>
  </div>
</div>

<div class="page-header">
  <h1>ログイン</h1>
</div>

  <div id="notice-message" class="alert alert-danger" role="alert">Wrong username or password</div>

<div class="container">
  <form class="form-horizontal" role="form" action="/login" method="POST">
    <div class="form-group">
      <label for="input-username" class="col-sm-3 control-label">お客様ご契約ID</label>
      <div class="col-sm-9">
        <input id="input-username" type="text" class="form-control" placeholder="半角英数字" name="login">
      </div>
    </div>
    <div class="form-group">
      <label for="input-password" class="col-sm-3 control-label">パスワード</label>
      <div class="col-sm-9">
        <input type="password" class="form-control" id="input-password" name="password" placeholder="半角英数字・記号（２文字以上）">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-primary btn-lg btn-block">ログイン</button>
      </div>
    </div>
  </form>
</div>

    </div>

  </body>
</html>
		`))
	} else if param == "invalid" {
		c.Data(200, "text/html", []byte(`
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <script id="css">
    document.write('<link rel="stylesheet" href="/stylesheets/bootstrap.min.css"> <link rel="stylesheet" href="/stylesheets/bootflat.min.css"> <link rel="stylesheet" href="/stylesheets/isucon-bank.css">');
    script = document.getElementById('css');
    script.parentNode.removeChild(script);
    </script>
    <title>isucon4</title>
  </head>
  <body>
    <div class="container">
      <h1 id="topbar">
        <a href="/">
          <script id="img">
          document.write('<img src="/images/isucon-bank.png" alt="いすこん銀行 オンラインバンキングサービス">');
          script = document.getElementById('img');
          script.parentNode.removeChild(script);
          </script>
        </a>
      </h1>
      <div id="be-careful-phising" class="panel panel-danger">
  <div class="panel-heading">
    <span class="hikaru-mozi">偽画面にご注意ください！</span>
  </div>
  <div class="panel-body">
    <p>偽のログイン画面を表示しお客様の情報を盗み取ろうとする犯罪が多発しています。</p>
    <p>ログイン直後にダウンロード中や、見知らぬウィンドウが開いた場合、<br>すでにウィルスに感染している場合がございます。即座に取引を中止してください。</p>
    <p>また、残高照会のみなど、必要のない場面で乱数表の入力を求められても、<br>絶対に入力しないでください。</p>
  </div>
</div>

<div class="page-header">
  <h1>ログイン</h1>
</div>

  <div id="notice-message" class="alert alert-danger" role="alert">You must be logged in</div>

<div class="container">
  <form class="form-horizontal" role="form" action="/login" method="POST">
    <div class="form-group">
      <label for="input-username" class="col-sm-3 control-label">お客様ご契約ID</label>
      <div class="col-sm-9">
        <input id="input-username" type="text" class="form-control" placeholder="半角英数字" name="login">
      </div>
    </div>
    <div class="form-group">
      <label for="input-password" class="col-sm-3 control-label">パスワード</label>
      <div class="col-sm-9">
        <input type="password" class="form-control" id="input-password" name="password" placeholder="半角英数字・記号（２文字以上）">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-primary btn-lg btn-block">ログイン</button>
      </div>
    </div>
  </form>
</div>

    </div>

  </body>
</html>
		`))
	} else if param == "locked" {
		c.Data(200, "text/html", []byte(`
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <script id="css">
    document.write('<link rel="stylesheet" href="/stylesheets/bootstrap.min.css"> <link rel="stylesheet" href="/stylesheets/bootflat.min.css"> <link rel="stylesheet" href="/stylesheets/isucon-bank.css">');
    script = document.getElementById('css');
    script.parentNode.removeChild(script);
    </script>
    <title>isucon4</title>
  </head>
  <body>
    <div class="container">
      <h1 id="topbar">
        <a href="/">
          <script id="img">
          document.write('<img src="/images/isucon-bank.png" alt="いすこん銀行 オンラインバンキングサービス">');
          script = document.getElementById('img');
          script.parentNode.removeChild(script);
          </script>
        </a>
      </h1>
      <div id="be-careful-phising" class="panel panel-danger">
  <div class="panel-heading">
    <span class="hikaru-mozi">偽画面にご注意ください！</span>
  </div>
  <div class="panel-body">
    <p>偽のログイン画面を表示しお客様の情報を盗み取ろうとする犯罪が多発しています。</p>
    <p>ログイン直後にダウンロード中や、見知らぬウィンドウが開いた場合、<br>すでにウィルスに感染している場合がございます。即座に取引を中止してください。</p>
    <p>また、残高照会のみなど、必要のない場面で乱数表の入力を求められても、<br>絶対に入力しないでください。</p>
  </div>
</div>

<div class="page-header">
  <h1>ログイン</h1>
</div>

  <div id="notice-message" class="alert alert-danger" role="alert">This account is locked.</div>

<div class="container">
  <form class="form-horizontal" role="form" action="/login" method="POST">
    <div class="form-group">
      <label for="input-username" class="col-sm-3 control-label">お客様ご契約ID</label>
      <div class="col-sm-9">
        <input id="input-username" type="text" class="form-control" placeholder="半角英数字" name="login">
      </div>
    </div>
    <div class="form-group">
      <label for="input-password" class="col-sm-3 control-label">パスワード</label>
      <div class="col-sm-9">
        <input type="password" class="form-control" id="input-password" name="password" placeholder="半角英数字・記号（２文字以上）">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-primary btn-lg btn-block">ログイン</button>
      </div>
    </div>
  </form>
</div>

    </div>

  </body>
</html>
		`))
	} else {
		c.Data(200, "text/html", []byte(`
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <script id="css">
    document.write('<link rel="stylesheet" href="/stylesheets/bootstrap.min.css"> <link rel="stylesheet" href="/stylesheets/bootflat.min.css"> <link rel="stylesheet" href="/stylesheets/isucon-bank.css">');
    script = document.getElementById('css');
    script.parentNode.removeChild(script);
    </script>
    <title>isucon4</title>
  </head>
  <body>
    <div class="container">
      <h1 id="topbar">
        <a href="/">
          <script id="img">
          document.write('<img src="/images/isucon-bank.png" alt="いすこん銀行 オンラインバンキングサービス">');
          script = document.getElementById('img');
          script.parentNode.removeChild(script);
          </script>
        </a>
      </h1>
      <div id="be-careful-phising" class="panel panel-danger">
  <div class="panel-heading">
    <span class="hikaru-mozi">偽画面にご注意ください！</span>
  </div>
  <div class="panel-body">
    <p>偽のログイン画面を表示しお客様の情報を盗み取ろうとする犯罪が多発しています。</p>
    <p>ログイン直後にダウンロード中や、見知らぬウィンドウが開いた場合、<br>すでにウィルスに感染している場合がございます。即座に取引を中止してください。</p>
    <p>また、残高照会のみなど、必要のない場面で乱数表の入力を求められても、<br>絶対に入力しないでください。</p>
  </div>
</div>

<div class="page-header">
  <h1>ログイン</h1>
</div>


<div class="container">
  <form class="form-horizontal" role="form" action="/login" method="POST">
    <div class="form-group">
      <label for="input-username" class="col-sm-3 control-label">お客様ご契約ID</label>
      <div class="col-sm-9">
        <input id="input-username" type="text" class="form-control" placeholder="半角英数字" name="login">
      </div>
    </div>
    <div class="form-group">
      <label for="input-password" class="col-sm-3 control-label">パスワード</label>
      <div class="col-sm-9">
        <input type="password" class="form-control" id="input-password" name="password" placeholder="半角英数字・記号（２文字以上）">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-primary btn-lg btn-block">ログイン</button>
      </div>
    </div>
  </form>
</div>

    </div>

  </body>
</html>
		`))
	}
}

func loadLoginLog(c *gin.Context) {
	storage.LoadOnMemory()
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
	storage.FlushLoginLog()
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
	session.Values["user_id"] = user.ID
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

	r.Run(":80")
}
