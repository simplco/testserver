package main

import (
	"fmt"
	"net/http"
	"time"

	uuid "github.com/satori/go.uuid"
)

func getUser(w http.ResponseWriter, req *http.Request) user {
	// get cookie
	c, err := req.Cookie("session")
	if err != nil {
		sID, _ := uuid.NewV4()
		c = &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}

	}
	c.MaxAge = sessionLength
	http.SetCookie(w, c)

	// if the user exists already, get user
	var u user
	if s, ok := dbSessions[c.Value]; ok {
		s.lastActivity = time.Now()
		dbSessions[c.Value] = s
		u = dbUsers[s.un]
	}
	return u
}

func alreadyLoggedIn(w http.ResponseWriter, req *http.Request) bool {
	c, err := req.Cookie("session")
	if err != nil {
		return false
	}
	s, ok := dbSessions[c.Value]
	if ok {
		s.lastActivity = time.Now()
		dbSessions[c.Value] = s
	}

	_, ok = dbUsers[s.un]

	c.MaxAge = sessionLength
	http.SetCookie(w, c)
	return ok
}

func cleanSessions() {
	fmt.Println("PRE-CLEAN")
	showSessions()

	for k, v := range dbSessions {
		if time.Now().Sub(v.lastActivity) > (time.Second*30) || v.un == "" {
			delete(dbSessions, k)
		}
	}

	dbSessionsCleaned = time.Now()
	fmt.Println("POST-CLEAN")
	showSessions()
}

func showSessions() {
	fmt.Println("----")
	for k, v := range dbSessions {
		fmt.Println(k, v.un)
	}
	fmt.Println("----")
}
