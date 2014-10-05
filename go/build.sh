#!/bin/bash

go get github.com/gin-gonic/gin
go get github.com/gorilla/sessions
go get github.com/go-sql-driver/mysql
go build -o golang-webapp .
