package gocas

import (
	"net/http"

	"github.com/golang/glog"
)

//Handler ...
func (c *Client) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if glog.V(2) {
			glog.Infof("cas: handling %v request for %v", r.Method, r.URL)
		}

		//If you don't get the session, the
		//client will never be logged in
		c.GetSession(w, r)

		setClient(r, c)

		if !IsAuthenticated(r) {
			RedirectToLogin(w, r, nil, c)
			return
		}

		if r.URL.Path == "/logout" {
			RedirectToLogout(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

//AllowAnonHandler ...
func (c *Client) AllowAnonHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if glog.V(2) {
			glog.Infof("cas: handling %v request for %v", r.Method, r.URL)
		}

		//If you don't get the session, the
		//client will never be logged in
		c.GetSession(w, r)

		setClient(r, c)

		if r.URL.Path == "/logout" {
			RedirectToLogout(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}
