package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
)

var (
	ctx     = context.Background()
	eveConf = &oauth2.Config{
		ClientID:     os.Getenv("EVE_CLIENT_ID"),
		ClientSecret: os.Getenv("EVE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:4000/auth/callback/eve",
		Scopes:       []string{"publicData"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.eveonline.com/oauth/authorize/",
			TokenURL: "https://login.eveonline.com/oauth/token",
		},
	}
	discordConf = &oauth2.Config{
		ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:4000/auth/callback/discord",
		Scopes:       []string{"identify"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discordapp.com/api/oauth2/authorize",
			TokenURL: "https://discordapp.com/api/oauth2/token",
		},
	}
)

type authHandler struct {
	next http.Handler
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("auth"); err == http.ErrNoCookie || cookie.Value == "" {
		// not authenticated
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusTemporaryRedirect)
	} else if err != nil {
		// some other error
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		// success - call the next handler
		h.next.ServeHTTP(w, r)
	}
}

// MustAuth is a helper function which creates an authHandler that wraps any
// other http.Handler
func MustAuth(handler http.Handler) http.Handler {
	return &authHandler{next: handler}
}

// loginHandler handles the Eve SSO login process
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if eveConf.ClientID == "" || eveConf.ClientSecret == "" {
		log.Fatalln("No clientID or ClientSecret: Did you remember to set environment variables?")
	}

	segs := strings.Split(r.URL.Path, "/")
	action := segs[2]
	service := segs[3]

	switch action {

	case "login":
		url, err := authCodeURL(service)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, url, http.StatusTemporaryRedirect)

	case "callback":
		if service == "eve" {
			r.ParseForm()
			code := r.FormValue("code")
			tok, err := eveConf.Exchange(ctx, code)
			if err != nil {
				w.Write([]byte(fmt.Sprintf("error exchanging auth code: %s", err)))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if !tok.Valid() {
				w.Write([]byte("Invalid token received from provider"))
				return
			}

			authenticatedClient := eveConf.Client(ctx, tok)
			resp, err := authenticatedClient.Get("https://login.eveonline.com/oauth/verify")
			if err != nil {
				w.Write([]byte(fmt.Sprintf("error verifying: %s", err)))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			buf, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				w.Write([]byte(fmt.Sprintf("error reading resp.Body: %s", err)))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			info := CharacterInfo{}
			if err := json.Unmarshal(buf, &info); err != nil {
				w.Write([]byte(fmt.Sprintf("error unmarshalling: %s", err)))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// This is a basic cookie... it is not safe, it is very very bad.
			http.SetCookie(w, &http.Cookie{
				Name:  "auth",
				Value: info.cookieValue(),
				Path:  "/"})

			// go back to user page
			http.Redirect(w, r, "/user", http.StatusTemporaryRedirect)
			return
		}

		if service == "discord" {
			r.ParseForm()
			code := r.FormValue("code")

			tok, err := discordConf.Exchange(ctx, code)
			if err != nil {
				w.Write([]byte(fmt.Sprintf("error exchanging auth code: %s", err)))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if !tok.Valid() {
				w.Write([]byte("Invalid token received from provider"))
				return
			}

			authenticatedClient := discordConf.Client(ctx, tok)
			resp, err := authenticatedClient.Get("https://discordapp.com/api/v6/users/@me")
			if err != nil {
				w.Write([]byte(fmt.Sprintf("error getting user: %s", err)))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			buf, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				w.Write([]byte(fmt.Sprintf("error reading resp.Body: %s", err)))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Write(buf)
		}

	default:
		w.Write([]byte(fmt.Sprintf("Auth action %s not supported", action)))
		w.WriteHeader(http.StatusNotFound)
	}

}

func authCodeURL(service string) (string, error) {
	switch service {
	case "eve":
		url := eveConf.AuthCodeURL("state", oauth2.AccessTypeOffline)
		return url, nil
	case "discord":
		url := discordConf.AuthCodeURL("state", oauth2.AccessTypeOnline)
		return url, nil
	default:
		return "", fmt.Errorf("service %s is not supported", service)
	}
}
