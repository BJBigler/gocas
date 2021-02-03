package gocas

import (
	"fmt"
	"net/http"

	"github.com/bjbigler/database"
	pexl "github.com/bjbigler/pexl/repository"
	princetonSeminars "github.com/bjbigler/princeton-seminars/repository"
)

//CASAuthenticatedUser checked for CAS authentication and returns an application user if so.
//Non-authenticated users are redirected to /login.
func CASAuthenticatedUser(db *database.DB, w http.ResponseWriter, r *http.Request, sendJSONMessage bool) (*princetonSeminars.User, error) {

	if !IsAuthenticated(r) {
		RedirectToLogin(w, r, nil, nil)
		return princetonSeminars.BlankUser(""), nil
	}

	netid := Username(r)

	return princetonSeminars.GetUser(db, netid)

	//TODO: Does this extra write take too much time?
	//user.LastVisited = database.GetNullTime(time.Now())
	//user.Persist()
}

//GetJSONCASAuthenticatedUser authenticates user. Non-authenticated users aren't redirected, but instead an error is returned
func GetJSONCASAuthenticatedUser(db *database.DB, w http.ResponseWriter, r *http.Request, sendJSONMessage bool) (*princetonSeminars.User, error) {
	if !IsAuthenticated(r) {
		noUser := princetonSeminars.BlankUser("")
		noUser.IsLoggedOut = true
		return noUser, fmt.Errorf("user not authenticated")
	}

	netid := Username(r)
	return princetonSeminars.GetUser(db, netid)
}

//GetCASAuthenticatedPexlUser checked for CAS authentication and returns an application user if so.
//Non-authenticated users are redirected to /login.
func GetCASAuthenticatedPexlUser(db *database.DB, w http.ResponseWriter, r *http.Request) (*pexl.User, error) {
	if !IsAuthenticated(r) {
		RedirectToLogin(w, r, nil, nil)
		return pexl.BlankUser(""), fmt.Errorf("user not authenticated")
	}

	netid := Username(r)

	//netid = "ddh2"

	return pexl.UserFromNetid(db, netid)

}

//GetJSONCASAuthenticatedPexlUser authenticates user. Non-authenticated users aren't redirected, but instead an error is returned
func GetJSONCASAuthenticatedPexlUser(db *database.DB, w http.ResponseWriter, r *http.Request, sendJSONMessage bool) (*pexl.User, error) {
	if !IsAuthenticated(r) {
		noUser := pexl.BlankUser("")
		return noUser, fmt.Errorf("user not authenticated")
	}

	netid := Username(r)

	//TODO: Refactor to return this error
	user, _ := pexl.UserFromNetid(db, netid)
	return user, nil
}
