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

type Logger struct {
	// True:  All login_log is on memory, insert query will be not executed but queued
	// False: Load and insert login_log by executing mysql query
	OnMemoryMode  bool

	failCountByIp map[string]int
}

func NewLogger() *Logger {
	return &Logger{
		OnMemoryMode: false,
	}
}

// Loads all login_log from mysql, and enables OnMemoryMode.
// Then all methods' return value will be decided by logger's internal variables.
func (l *Logger) LoadLoginLog() {
	// Initialize logger
	l.OnMemoryMode = true
	l.failCountByIp = make(map[string]int)

	for i := 0; i < 7; i++ {
		rows, err := db.Query(
			"SELECT created_at, user_id, login, ip, succeeded FROM login_log WHERE id BETWEEN ? AND ?;",
			1 + i * 10000, (i+1) * 10000,
		)

		if err != nil {
			panic("This should not raise error")
		}

		log := &LoginLog{}
		for rows.Next() {
			rows.Scan(&log.CreatedAt, &log.UserId, &log.Login, &log.Ip, &log.Succeeded)
			l.applyLoginLog(log)
		}

		rows.Close()
	}
}

// Inserts all queued login_log by bulk insert.
// Then disable OnMemoryMode.
func (l *Logger) FlushLoginLog() {
	l.OnMemoryMode = false
	l.failCountByIp = map[string]int{}
}

func (l *Logger) Post(log *LoginLog) error {
	if l.OnMemoryMode {
		l.queueLoginLog(log)
		l.applyLoginLog(log)
		return l.insertLoginLog(log) // TODO: This should be removed later
	} else {
		return l.insertLoginLog(log)
	}
}

// Apply login_log to logger's internal variables.
func (l *Logger) applyLoginLog(log *LoginLog) error {
	if log.Succeeded {
		l.failCountByIp[log.Ip] = 0
	} else {
		l.failCountByIp[log.Ip]++
	}

	return nil
}

// Queue login_log. It will be executed by FlushLoginLog().
func (l *Logger) queueLoginLog(log *LoginLog) error {
	// TODO: implement
	return nil
}

// Direct logging to mysql.
func (l *Logger) insertLoginLog(log *LoginLog) error {
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
func (l *Logger) isLockedUserId(userId int) (bool, error) {
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
func (l *Logger) isBannedIP(ip string) (bool, error) {
	var failCount int

	if l.OnMemoryMode {
		failCount = l.failCountByIp[ip]
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
func (l *Logger) lastLoginOfUserId(userId int) *LastLogin {
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
