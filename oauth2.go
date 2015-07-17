// Copyright 2014 GoIncremental Limited. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package oauth2 contains Negroni middleware to provide
// user login via an OAuth 2.0 backend.

package oauth2

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/codegangsta/negroni"
	sessions "github.com/goincremental/negroni-sessions"
	"golang.org/x/oauth2"
)

const (
	codeRedirect = 302
	keyToken     = "oauth2_token"
	keyNextPage  = "next"
	keyState     = "state"
	keyProvider  = "provider"

	// PathLogin sets the path to handle OAuth 2.0 logins.
	pathLogin = "/login"
	// PathLogout sets to handle OAuth 2.0 logouts.
	pathLogout = "/logout"
	// PathCallback sets the path to handle callback from OAuth 2.0 backend
	// to exchange credentials.
	pathCallback = "/oauth2callback"
	// PathError sets the path to handle error cases.
	pathError = "/oauth2error"
	// the provider
	provider = "provider"
)

type Oauth2Handler struct {
	Provider     string
	PathLogin    string
	PathLogout   string
	PathCallback string
	PathError    string
	Config       *oauth2.Config
}

type Token struct {
	*oauth2.Token
}

func (h *Oauth2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	s := sessions.GetSession(r)

	if r.Method == "GET" {
		switch r.URL.Path {
		case h.PathLogin:
			h.login(s, w, r)
		case h.PathLogout:
			h.logout(s, w, r)
		case h.PathCallback:
			h.handleOAuth2Callback(s, w, r)
		default:
			next(w, r)
		}
	} else {
		next(w, r)
	}
}

func (h *Oauth2Handler) login(s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get(keyNextPage)

	if s.Get(keyToken) == nil {
		// User is not logged in.
		if next == "" {
			next = "/"
		}

		state := newState()
		// store the next url and state token in the session
		s.Set(keyState, state)
		s.Set(keyNextPage, next)
		s.Set(keyProvider, h.Provider)
		http.Redirect(w, r, h.Config.AuthCodeURL(state, oauth2.AccessTypeOffline), http.StatusFound)
		return
	}
	// No need to login, redirect to the next page.
	http.Redirect(w, r, next, http.StatusFound)
}

func (h *Oauth2Handler) logout(s sessions.Session, w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get(keyNextPage)
	s.Delete(keyToken)
	s.Delete("email")
	s.Delete(keyProvider)
	http.Redirect(w, r, next, http.StatusFound)
}

func (h *Oauth2Handler) handleOAuth2Callback(s sessions.Session, w http.ResponseWriter, r *http.Request) {
	providedState := r.URL.Query().Get("state")
	fmt.Printf("Got state from request %s\n", providedState)

	//verify that the provided state is the state we generated
	//if it is not, then redirect to the error page
	originalState := s.Get(keyState)
	fmt.Printf("Got state from session %s\n", originalState)
	if providedState != originalState {
		http.Redirect(w, r, h.PathError, http.StatusFound)
		return
	}

	next := s.Get(keyNextPage).(string)
	fmt.Printf("Got a next page from the session: %s\n", next)
	code := r.URL.Query().Get("code")
	t, err := h.Config.Exchange(oauth2.NoContext, code)
	if err != nil {
		// Pass the error message, or allow dev to provide its own
		// error handler.
		http.Redirect(w, r, h.PathError, http.StatusFound)
		return
	}

	// Store the credentials in the session.
	val, _ := json.Marshal(t)
	s.Set(keyToken, val)
	http.Redirect(w, r, next, http.StatusFound)
}

type Config oauth2.Config

// Returns a new Google OAuth 2.0 backend endpoint.
func Google(config *Config) negroni.Handler {
	authUrl := "https://accounts.google.com/o/oauth2/auth"
	tokenUrl := "https://accounts.google.com/o/oauth2/token"
	return NewOAuth2Provider(config, authUrl, tokenUrl)
}

// Returns a new Github OAuth 2.0 backend endpoint.
func Github(config *Config) negroni.Handler {
	authUrl := "https://github.com/login/oauth/authorize"
	tokenUrl := "https://github.com/login/oauth/access_token"
	return NewOAuth2Provider(config, authUrl, tokenUrl)
}

func Facebook(config *Config) negroni.Handler {
	authUrl := "https://www.facebook.com/dialog/oauth"
	tokenUrl := "https://graph.facebook.com/oauth/access_token"
	return NewOAuth2Provider(config, authUrl, tokenUrl)
}

func LinkedIn(config *Config) negroni.Handler {
	authUrl := "https://www.linkedin.com/uas/oauth2/authorization"
	tokenUrl := "https://www.linkedin.com/uas/oauth2/accessToken"
	return NewOAuth2Provider(config, authUrl, tokenUrl)
}

// Returns a generic OAuth 2.0 backend endpoint.
func NewOAuth2Provider(config *Config, authUrl, tokenUrl string) negroni.Handler {
	c := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Scopes:       config.Scopes,
		RedirectURL:  config.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authUrl,
			TokenURL: tokenUrl,
		},
	}

	h := &Oauth2Handler{
		Provider:     provider,
		PathLogin:    pathLogin,
		PathLogout:   pathLogout,
		PathCallback: pathCallback,
		PathError:    pathError,
		Config:       c,
	}

	return h
}

func GetToken(r *http.Request) *Token {
	s := sessions.GetSession(r)
	t := unmarshallToken(s)

	//not doing this doesn't pass through the
	//nil return, causing a test to fail - not sure why??
	if t == nil {
		return nil
	} else {
		return t
	}
}

func SetToken(r *http.Request, t interface{}) {
	s := sessions.GetSession(r)
	val, _ := json.Marshal(t)
	s.Set(keyToken, val)
	//Check immediately to see if the token is expired
	tk := unmarshallToken(s)
	if tk != nil {
		// check if the access token is expired
		if !tk.Valid() && tk.RefreshToken == "" {
			s.Delete(keyToken)
			s.Delete("email")
			s.Delete(keyProvider)
			tk = nil
		}
	}
}

func newState() string {
	var p [16]byte
	_, err := rand.Read(p[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(p[:])
}

func unmarshallToken(s sessions.Session) *Token {

	if s.Get(keyToken) == nil {
		return nil
	}

	data := s.Get(keyToken).([]byte)
	var tk oauth2.Token
	json.Unmarshal(data, &tk)
	return &Token{&tk}

}
