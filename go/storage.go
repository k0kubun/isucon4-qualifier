package main

import (
	"time"
	"database/sql"
	"fmt"
)

type LoginLog struct {
	CreatedAt time.Time
	UserId    int
	Login     string
	Ip        string
	Succeeded bool
}

type Storage struct {
	// True:  All login_log is on memory, insert query will be not executed but queued
	// False: Load and insert login_log by executing mysql query
	OnMemoryMode bool

	failCountByUserId    map[int]int
	failCountByIp        map[string]int
	userByLogin          map[string]*User
	userById             map[int]*User
	currentLoginByUserId map[int]*LastLogin
	lastLoginByUserId    map[int]*LastLogin
	queue                []LoginLog
}

func NewStorage() *Storage {
	return &Storage{
		OnMemoryMode: false,
	}
}

func (s *Storage) EnableOnMemoryMode() {
	s.OnMemoryMode = true
	s.failCountByUserId = make(map[int]int, 200000)
	s.failCountByIp = make(map[string]int, 100000)
	s.userByLogin = make(map[string]*User, 200000)
	s.userById = make(map[int]*User, 200000)
	s.currentLoginByUserId = make(map[int]*LastLogin, 200000)
	s.lastLoginByUserId = make(map[int]*LastLogin, 200000)
	s.queue = []LoginLog{}
}

func (s *Storage) DisableOnMemoryMode() {
	s.OnMemoryMode = false
	s.failCountByUserId = map[int]int{}
	s.failCountByIp = map[string]int{}
	s.userByLogin = map[string]*User{}
	s.userById = map[int]*User{}
	s.currentLoginByUserId = map[int]*LastLogin{}
	s.lastLoginByUserId = map[int]*LastLogin{}
	s.queue = []LoginLog{}
}

// Loads all data from mysql, and enables OnMemoryMode.
// Then all methods' return value will be decided by storage's internal variables.
func (s *Storage) LoadOnMemory() {
	s.EnableOnMemoryMode()

	for i := 0; i < 7; i++ {
		rows, _ := db.Query(
			"SELECT created_at, user_id, login, ip, succeeded FROM login_log WHERE id BETWEEN ? AND ?;",
			1 + i * 10000, (i+1) * 10000,
		)

		log := &LoginLog{}
		for rows.Next() {
			rows.Scan(&log.CreatedAt, &log.UserId, &log.Login, &log.Ip, &log.Succeeded)
			s.applyLoginLog(log)
		}

		rows.Close()
	}

	for i := 0; i < 20; i++ {
		rows, _ := db.Query(
			"SELECT id, login, password_hash, salt FROM users WHERE id BETWEEN ? AND ?;",
			1 + i * 10000, (i+1) * 10000,
		)

		for rows.Next() {
			user := new(User)
			rows.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)
			s.userByLogin[user.Login] = user
			s.userById[user.ID] = user
		}

		rows.Close()
	}
}

// Inserts all queued login_log by bulk insert.
// Then disable OnMemoryMode.
func (s *Storage) FlushLoginLog() {
	batchSize := 500
	length := len(s.queue)

	for i := 0; i * batchSize < length; i++ {
		startPos := i * batchSize
		endPos := (i+1) * batchSize
		if endPos > length {
			endPos = length
		}
		s.bulkInsertLoginLog(s.queue[startPos:endPos])
	}

	s.DisableOnMemoryMode()
}

// Logging interface with storage switching
func (s *Storage) PostLoginLog(log *LoginLog) error {
	if s.OnMemoryMode {
		s.queueLoginLog(log)
		return s.applyLoginLog(log)
	} else {
		return s.insertLoginLog(log)
	}
}

// Apply login_log to storage's internal variables.
func (s *Storage) applyLoginLog(log *LoginLog) error {
	if log.Succeeded {
		s.failCountByIp[log.Ip] = 0
		s.failCountByUserId[log.UserId] = 0

		s.lastLoginByUserId[log.UserId] = s.currentLoginByUserId[log.UserId]
		s.currentLoginByUserId[log.UserId] = &LastLogin{
			Login:     log.Login,
			IP:        log.Ip,
			CreatedAt: log.CreatedAt,
		}
	} else {
		s.failCountByIp[log.Ip]++
		s.failCountByUserId[log.UserId]++
	}

	return nil
}

// Queue login_log. It will be executed by FlushLoginLog().
func (s *Storage) queueLoginLog(log *LoginLog) {
	s.queue = append(s.queue, *log)
}

func (s *Storage) bulkInsertLoginLog(logs []LoginLog) {
	values := ""

	lastIndex := len(logs) - 1
	for i, log := range logs {
		succ := 0
		if log.Succeeded {
			succ = 1
		}

		values += fmt.Sprintf("('%s',%d,'%s','%s',%d)", log.CreatedAt.Format("2006-01-02 15:04:05"), log.UserId, log.Login, log.Ip, succ)
		if i != lastIndex {
			values += ","
		}
	}

	query := fmt.Sprintf("INSERT INTO login_log(created_at, user_id, login, ip, succeeded) VALUES %s ON DUPLICATE KEY UPDATE login_log.created_at=VALUES(created_at), login_log.user_id=VALUES(user_id), login_log.login=VALUES(login), login_log.ip=VALUES(ip), login_log.succeeded=VALUES(succeeded);", values)
	db.Exec(query)
}

// Direct logging to mysql.
func (s *Storage) insertLoginLog(log *LoginLog) error {
	succ := 0
	if log.Succeeded {
		succ = 1
	}

	var userId sql.NullInt64
	userId.Int64 = int64(log.UserId)
	userId.Valid = true

	_, err := db.Exec(
		"INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) "+
			"VALUES (?,?,?,?,?)",
		log.CreatedAt, userId, log.Login, log.Ip, succ,
	)

	return err
}

// Whether login failure count for userId is over threshold or not
func (s *Storage) isLockedUserId(userId int) (bool, error) {
	var failCount int

	if s.OnMemoryMode {
		failCount = s.failCountByUserId[userId]
	} else {
		var ni sql.NullInt64

		row := db.QueryRow(
			"SELECT COUNT(1) AS failures FROM login_log WHERE "+
				"user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND "+
				"succeeded = 1 ORDER BY id DESC LIMIT 1), 0);",
			userId, userId,
		)
		err := row.Scan(&ni)

		switch {
		case err == sql.ErrNoRows:
			return false, nil
		case err != nil:
			return false, err
		}

		failCount = int(ni.Int64)
	}

	return UserLockThreshold <= failCount, nil
}

// Whether login failure count for ip is over threshold or not
func (s *Storage) isBannedIP(ip string) (bool, error) {
	var failCount int

	if s.OnMemoryMode {
		failCount = s.failCountByIp[ip]
	} else {
		var ni sql.NullInt64

		row := db.QueryRow(
			"SELECT COUNT(1) AS failures FROM login_log WHERE "+
				"ip = ? AND id > IFNULL((select id from login_log where ip = ? AND "+
				"succeeded = 1 ORDER BY id DESC LIMIT 1), 0);",
			ip, ip,
		)
		err := row.Scan(&ni)

		switch {
		case err == sql.ErrNoRows:
			return false, nil
		case err != nil:
			return false, err
		}

		failCount = int(ni.Int64)
	}

	return IPBanThreshold <= failCount, nil
}

// [last_login, current_login].compact.first
func (s *Storage) lastLoginOfUserId(userId int) *LastLogin {
	var lastLogin *LastLogin

	if s.OnMemoryMode {
		lastLogin = s.lastLoginByUserId[userId]

		if lastLogin != nil {
			return lastLogin
		} else {
			return s.currentLoginByUserId[userId]
		}
	} else {
		rows, err := db.Query(
			"SELECT login, ip, created_at FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2",
			userId,
		)

		if err != nil {
			return nil
		}

		defer rows.Close()
		for rows.Next() {
			lastLogin = &LastLogin{}
			err = rows.Scan(&lastLogin.Login, &lastLogin.IP, &lastLogin.CreatedAt)
			if err != nil {
				return nil
			}
		}

		return lastLogin
	}
}

func (s *Storage) userByLoginName(loginName string) *User {
	if s.OnMemoryMode {
		if user, ok := s.userByLogin[loginName]; ok {
			return user
		} else {
			return nil
		}
	} else {
		user := &User{}

		row := db.QueryRow(
			"SELECT id, login, password_hash, salt FROM users WHERE login = ?",
			loginName,
		)
		err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)
		if err != nil {
			return nil
		}

		return user
	}
}

func (s *Storage) userByUserId(userId interface{}) *User {
	if s.OnMemoryMode {
		return s.userById[userId.(int)]
	} else {
		user := &User{}
		row := db.QueryRow(
			"SELECT id, login, password_hash, salt FROM users WHERE id = ?",
			userId,
		)
		err := row.Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt)

		if err != nil {
			return nil
		}

		return user
	}
}
