package gocas

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/bjbigler/database"
	"github.com/golang/glog"
)

//Options for client configuration
type Options struct {
	Context      context.Context
	URL          *url.URL     // URL to the CAS service
	Store        TicketStore  // Custom TicketStore, if nil a MemoryStore will be used
	SessionStore SessionStore //Custom SessionStore, for CGI and AppEngine-type environments, where session state isn't maintained or disappears periodically
	Domain       string       //cookie domain
	Client       *http.Client // Custom http client to allow options for http connections
	SendService  bool         // Custom sendService to determine whether you need to send service param
	RunOnLogin   RunOnLogin   //Provides functionality to run a function post-login
	//ServiceURLRequiresTrailingSlash bool
	DB *database.DB //Added by BJBigler; should be connection to DB providing store if using MySql
	// UseMySQLSessions  bool                             //Added by BJBigler to accomodate CGI, which doesn't have server sessions.
	// FirestoreSessions bool                             //Added BJBigler to accomodate CGI using Firestore as the backend DB
	// RunOnLogin   func(*database.DB, string) error //func to run on login; string should be the netid
	// RunOnLoginDB *database.DB                     //DB to use when executing RunOnLogin

}

// Client implements the main protocol
type Client struct {
	context     context.Context
	URL         *url.URL
	tickets     TicketStore
	sessions    SessionStore
	client      *http.Client
	domain      string //cookie domain
	mu          sync.Mutex
	sendService bool
	runOnLogin  RunOnLogin
	db          *database.DB //Database connection
	//serviceURLRequiresTrailingSlash bool
	// useMySQLSessions     bool
	// useFirestoreSessions bool
	// runOnLogin   func(*database.DB, string) error //Function to run on login
	// runOnLoginDB *database.DB                     //Database connection for RunOnLogin
}

// NewClient creates a Client with the provided Options.
func NewClient(options *Options) *Client {

	if glog.V(2) {
		glog.Infof("cas: new client with options %v", options)
	}

	var tickets TicketStore
	if options.Store != nil {
		tickets = options.Store
	} else {
		tickets = &MemoryStore{}
	}

	var sessions SessionStore
	if options.SessionStore != nil {
		sessions = options.SessionStore
	} else {
		sessions = &SessionMemoryStore{
			store: make(map[string]string),
		}
	}

	var client *http.Client
	if options.Client != nil {
		client = options.Client
	} else {
		client = &http.Client{}
	}

	return &Client{
		context:     options.Context,
		URL:         options.URL,
		tickets:     tickets, //ticket store
		client:      client,
		domain:      options.Domain,
		sessions:    sessions,
		sendService: options.SendService,
		runOnLogin:  options.RunOnLogin,
		//serviceURLRequiresTrailingSlash: options.ServiceURLRequiresTrailingSlash,
		db: options.DB,
		// useMySQLSessions:     options.UseMySQLSessions,
		// useFirestoreSessions: options.FirestoreSessions,
		//runOnLoginDB: options.RunOnLoginDB,
	}
}

// Handle wraps a http.Handler to provide CAS authentication for the handler.
func (c *Client) Handle(h http.Handler) http.Handler {
	return &clientHandler{
		c: c,
		h: h,
	}
}

// HandleFunc wraps a function to provide CAS authentication for the handler function.
func (c *Client) HandleFunc(h func(http.ResponseWriter, *http.Request)) http.Handler {
	return c.Handle(http.HandlerFunc(h))
}

//requestURL determines an absolute URL from the http.Request.
func requestURL(r *http.Request, referer *url.URL) (*url.URL, error) {

	u := r.URL

	if referer != nil && referer.String() != "" {
		u = referer
	}

	u.Host = r.Host

	u.Scheme = "http"

	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		u.Scheme = scheme
	} else if r.TLS != nil {
		u.Scheme = "https"
	}

	return u, nil
}

// LoginURLForRequest determines the CAS login URL for the http.Request.
func (c *Client) LoginURLForRequest(r *http.Request, referer *url.URL) (string, error) {
	u, err := c.URL.Parse(path.Join(c.URL.Path, "login"))
	if err != nil {
		return "", err
	}

	service, err := requestURL(r, referer)
	if err != nil {
		return "", err
	}

	serviceURL := sanitisedURLString(service)

	fmt.Println("Service URL when creating LoginURL", serviceURL)

	q := u.Query()
	q.Add("service", serviceURL)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// LogoutURLForRequest determines the CAS logout URL for the http.Request.
func (c *Client) LogoutURLForRequest(r *http.Request) (string, error) {
	u, err := c.URL.Parse(path.Join(c.URL.Path, "logout"))
	if err != nil {
		return "", err
	}

	if c.sendService {
		service, err := requestURL(r, nil)
		if err != nil {
			return "", err
		}

		q := u.Query()
		q.Add("service", sanitisedURLString(service))
		u.RawQuery = q.Encode()
	}

	return u.String(), nil
}

// ServiceValidateURLForRequest determines the CAS serviceValidate URL for the ticket and http.Request.
func (c *Client) ServiceValidateURLForRequest(ticket string, r *http.Request) (string, error) {
	u, err := c.URL.Parse(path.Join(c.URL.Path, "serviceValidate"))
	if err != nil {
		return "", err
	}

	service, err := requestURL(r, nil)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("service", sanitisedURLString(service))
	q.Add("ticket", ticket)
	u.RawQuery = q.Encode()

	fmt.Println("Service URL when validating request", sanitisedURLString(service))
	return u.String(), nil
}

//ValidateURLForRequest determines the CAS validate URL for the ticket and http.Request.
func (c *Client) ValidateURLForRequest(ticket string, r *http.Request) (string, error) {
	fmt.Print("\nValidating ticket\n")

	u, err := c.URL.Parse(path.Join(c.URL.Path, "validate"))
	if err != nil {
		return "", err
	}

	service, err := requestURL(r, nil)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("service", sanitisedURLString(service))
	q.Add("ticket", ticket)
	u.RawQuery = q.Encode()

	fmt.Println("Service URL when validating URL for request", sanitisedURLString(service))

	return u.String(), nil
}

// RedirectToLogout replies to the request with a redirect URL to log out of CAS.
func (c *Client) RedirectToLogout(w http.ResponseWriter, r *http.Request) {
	u, err := c.LogoutURLForRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if glog.V(2) {
		glog.Info("Logging out, redirecting client to %v with status %v",
			u, http.StatusFound)
	}

	c.ClearSession(w, r)
	http.Redirect(w, r, u, http.StatusFound)
}

//RedirectToLogin replies to the request with a redirect URL to authenticate with CAS.
func (c *Client) RedirectToLogin(w http.ResponseWriter, r *http.Request, referer *url.URL) {

	u, err := c.LoginURLForRequest(r, referer)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if glog.V(2) {
		glog.Infof("Redirecting client to %v with status %v", u, http.StatusFound)
	}

	http.Redirect(w, r, u, http.StatusFound)
}

// validateTicket performs CAS ticket validation with the given ticket and service.
//
// If the request returns a 404 then validateTicketCas1 will be returned.
func (c *Client) validateTicket(ticket string, service *http.Request) error {

	if glog.V(2) {
		serviceURL, _ := requestURL(service, nil)
		glog.Infof("Validating ticket \n\t%v for service \n\t%v", ticket, serviceURL)
	}

	u, err := c.ServiceValidateURLForRequest(ticket, service)

	if err != nil {
		fmt.Println("Error getting ServiceValidateURLForRequest:", err)
		fmt.Println("Validate URL:", u)
		return err
	}

	r, err := http.NewRequest("GET", u, nil)
	if err != nil {
		if glog.V(2) {
			glog.Infof("Error getting NewRequest: %v", err)
		}
		return err
	}

	//r.Header.Add("User-Agent", "Golang CAS client gopkg.in/cas")

	if glog.V(2) {
		glog.Infof("Attempting ticket validation with %v", r.URL)
	}

	resp, err := c.client.Do(r)
	if err != nil {
		if glog.V(2) {
			glog.Infof("Error getting sending validation request: %v", err)
		}
		return err
	}

	if glog.V(2) {
		glog.Infof("Request method \n\t%v to URL \n\t%v returned \n\t%v",
			r.Method, r.URL,
			resp.Status)
	}

	if resp.StatusCode == http.StatusNotFound {
		return c.validateTicketCas1(ticket, service)
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		if glog.V(2) {
			glog.Infof("Error getting reading response body: %v", err)
		}
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cas: validate ticket: %v", string(body))
	}

	if glog.V(2) {
		glog.Infof("Received authentication response\n%v", string(body))
	}

	success, err := ParseServiceResponse(body)

	if err != nil {
		fmt.Printf("error ParsingServiceResponse: %v\n", err)
		return err
	}

	if glog.V(2) {
		glog.Infof("Parsed ServiceResponse: %#v", success)
	}

	if err := c.tickets.Write(ticket, success); err != nil {
		fmt.Printf("Error writing ticket: %v\n", err)
		return err
	}

	return nil
}

// validateTicketCas1 performs CAS protocol 1 ticket validation.
func (c *Client) validateTicketCas1(ticket string, service *http.Request) error {
	u, err := c.ValidateURLForRequest(ticket, service)
	if err != nil {
		return err
	}

	r, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}

	r.Header.Add("User-Agent", "Golang CAS client gopkg.in/cas")

	if glog.V(2) {
		glog.Info("Attempting ticket validation with %v", r.URL)
	}

	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}

	if glog.V(2) {
		glog.Info("Request %v %v returned %v",
			r.Method, r.URL,
			resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		return err
	}

	body := string(data)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cas: validate ticket: %v", body)
	}

	if glog.V(2) {
		glog.Infof("Received authentication response\n%v", body)
	}

	if body == "no\n\n" {
		return nil // not logged in
	}

	success := &AuthenticationResponse{
		User: body[4 : len(body)-1],
	}

	if glog.V(2) {
		glog.Infof("Parsed ServiceResponse: %#v", success)
	}

	if err := c.tickets.Write(ticket, success); err != nil {
		return err
	}

	return nil
}

// GetSession finds or creates a session for the request.
//
// A cookie is set on the response if one is not provided with the request.
// Validates the ticket if the URL parameter is provided.
func (c *Client) GetSession(w http.ResponseWriter, r *http.Request) error {

	//1) Get the cookie
	cookie := getCookie(w, r, c.domain)

	//2) The cookie holds the session key,
	//which we need to lookup the session value,
	//i.e., the ticket delivered from the CAS server
	sessionKey := cookie.Value

	//3) Grab the session value (i.e., ticket) from the session store,
	//if it's there. If not, then see (4)
	sessionValue, err := c.sessions.Read(sessionKey)

	if err != nil {
		return err
	}

	if sessionValue != "" {
		a, err := c.tickets.Read(sessionValue)
		if err == nil {
			setAuthenticationResponse(r, a)
			return nil
		}
	}

	//4) Set up session from URL ticket data...
	//if we've gotten this far, we have tried to read the authentication
	//stuff from our ticket store, but nothing was there. We'll need
	//to get it from the ticket and set up the rest.
	if ticket := r.URL.Query().Get("ticket"); ticket != "" {

		//Validate ticket by going back to the CAS server and asking for
		//the user's Netid.
		if err := c.validateTicket(ticket, r); err != nil {

			//Could not validate ticket,
			//so let the URL be served up without
			//the logged-in status
			if glog.V(2) {
				glog.Infof("Error validating ticket: %v", err)
			}
			return err // allow ServeHTTP()
		}

		//Put the ticket value into session
		err = c.sessions.Write(cookie.Value, ticket)

		if err != nil {
			return err
		}

		//Read ticket from session
		a, err := c.tickets.Read(ticket)

		if err != nil {
			clearCookie(w, cookie)
			return err
		}

		setAuthenticationResponse(r, a)

		if c.runOnLogin != nil {
			c.runOnLogin.Run(Username(r))
		}

		//Remove ticket from URL
		//http.Redirect(w, r, removeTicketFromURL(r.URL).String(), 302)
	}

	return nil
}

// getCookie finds or creates the session cookie on the response.
func getCookie(w http.ResponseWriter, r *http.Request, domain string) *http.Cookie {

	c, err := r.Cookie(sessionCookieName)

	if err != nil {

		if glog.V(2) {
			glog.Infof("Could not find cookie (%s) because of err %v. Creating a new one.", sessionCookieName, err)
		}

		// Intentionally not enabling HttpOnly so the cookie can
		//still be used by Ajax requests.
		c = &http.Cookie{
			HttpOnly: false,
			Name:     sessionCookieName,
			Value:    newSessionID(),
			MaxAge:   (90 * 24 * 60 * 60), //90 days
			Path:     "/",
			Domain:   domain,
		}

		if glog.V(2) {
			glog.Infof("Setting %v cookie with value: %v", c.Name, c.Value)
		}

		r.AddCookie(c) // so we can find it later if required
		http.SetCookie(w, c)
	}

	return c
}

func getTicketFromMySQL(db *database.DB, cookie *http.Cookie) (string, error) {

	session, err := getSessionFromMySQL(db, cookie.Value)

	if session != nil {
		return session.Value, nil
	}
	if glog.V(2) {
		glog.Infof("No session found using cooking value %s: ", cookie.Value)
	}
	return "", err
}

// newSessionID generates a new opaque session identifier for use in the cookie.
func newSessionID() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// generate 64 character string
	bytes := make([]byte, 64)
	rand.Read(bytes)

	for k, v := range bytes {
		bytes[k] = alphabet[v%byte(len(alphabet))]
	}

	return string(bytes)
}

// clearCookie invalidates and removes the cookie from the client.
func clearCookie(w http.ResponseWriter, c *http.Cookie) {
	c.MaxAge = -1
	http.SetCookie(w, c)
}

// SetSession maps the session-id-to-ticket in the Client.
func (c *Client) SetSession(id string, ticket string) error {
	return c.sessions.Write(id, ticket)
}

// ClearSession removes the session from the client and clears the cookie.
func (c *Client) ClearSession(w http.ResponseWriter, r *http.Request) {

	//Get the ticket before we delete the session.
	//We need the ticket to delete the DB record
	cookie := getCookie(w, r, c.domain)
	ticket, _ := c.sessions.Read(cookie.Value)
	err := c.tickets.Delete(ticket)

	if err != nil {
		fmt.Println("Could not delete ticket using cookie value", ticket, "\n", err)
	}

	c.sessions.Clear()

	// if c.useMySQLSessions {
	// 	ticket, _ := getTicketFromMySQL(c.db, cookie)
	// 	c.tickets.Delete(ticket)

	// 	deleteSessionInMySQL(c.db, cookie.Value)
	// } else if c.useFirestoreSessions {

	// 	session, err := c.firestoreService.UserSession.FromKey(cookie.Value)

	// 	if err != nil && session != nil {
	// 		c.tickets.Delete(session.Value)
	// 	}

	// } else {
	// 	if s, ok := c.sessions[cookie.Value]; ok {
	// 		if err := c.tickets.Delete(s); err != nil {
	// 			if glog.V(2) {
	// 				glog.Errorf("Failed to remove %v from %T: %v", cookie.Value, c.tickets, err)
	// 			}
	// 		}

	// 		c.deleteSession(s)
	// 	}
	// }
	clearCookie(w, cookie)
}

// deleteSession removes the session from the client
func (c *Client) deleteSession(id string) {
	c.sessions.Delete(id)
}

// findAndDeleteSessionWithTicket removes the session from the client via Single Log Out
//
// When a Single Log Out request is received we receive the service ticket identifier. This
// function loops through the sessions to find the matching session id. Once retrieved the
// session is removed from the client. When the session is next requested the GetSession
// function will notice the session is invalid and revalidate the user.
func (c *Client) findAndDeleteSessionWithTicket(ticket string) {
	c.sessions.DeleteFromTicket(ticket)
}
