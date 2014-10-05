package main

import (
	"time"
	"database/sql"
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
	OnMemoryMode  bool

	failCountByIp map[string]int
	userByLogin   map[string]*User
}

func NewStorage() *Storage {
	return &Storage{
		OnMemoryMode: false,
	}
}

func (s *Storage) EnableOnMemoryMode() {
	s.OnMemoryMode = true
	s.failCountByIp = make(map[string]int)
}

func (s *Storage) DisableOnMemoryMode() {
	s.OnMemoryMode = false
	s.failCountByIp = map[string]int{}
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
		}

		rows.Close()
	}
}

// Inserts all queued login_log by bulk insert.
// Then disable OnMemoryMode.
func (s *Storage) FlushLoginLog() {
	s.DisableOnMemoryMode()
}

// Logging interface with storage switching
func (s *Storage) PostLoginLog(log *LoginLog) error {
	if s.OnMemoryMode {
		s.queueLoginLog(log)
		s.applyLoginLog(log)
		return s.insertLoginLog(log) // TODO: This should be removed later
	} else {
		return s.insertLoginLog(log)
	}
}

// Apply login_log to storage's internal variables.
func (s *Storage) applyLoginLog(log *LoginLog) error {
	if log.Succeeded {
		s.failCountByIp[log.Ip] = 0
	} else {
		s.failCountByIp[log.Ip]++
	}

	return nil
}

// Queue login_log. It will be executed by FlushLoginLog().
func (s *Storage) queueLoginLog(log *LoginLog) error {
	// TODO: implement
	return nil
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
