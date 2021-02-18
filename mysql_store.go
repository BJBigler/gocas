package gocas

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/bjbigler/database"
	"github.com/bjbigler/utils"
	"github.com/golang/glog"
	"github.com/jmoiron/sqlx"
)

//MySQLTicketStore fields for MySql storage
type MySQLTicketStore struct {
	ID                     string                 `db:"t_id"`
	Data                   string                 `db:"t_data"` //stored in JSON format
	Created                database.NullTime      `db:"t_created"`
	Updated                database.NullTime      `db:"t_updated"`
	AuthenticationResponse AuthenticationResponse `db:"-"`
}

//MySQLStore implements the TicketStore interface
//to store ticket data in a database
type MySQLStore struct {
	mu    sync.RWMutex
	store *AuthenticationResponse
	DB    *database.DB //Database connection
}

// Read returns the AuthenticationResponse for a ticket
func (s *MySQLStore) Read(id string) (*AuthenticationResponse, error) {

	if id == "" {
		if glog.V(2) {
			glog.Infof("id passed into Read was blank.")
		}

		return nil, ErrInvalidTicket
	}

	s.mu.RLock()

	ticketStores := []*MySQLTicketStore{}

	var dbErr error
	parseRows := func(rows *sqlx.Rows) {
		for rows.Next() {
			var ts MySQLTicketStore
			dbErr = rows.StructScan(&ts)

			if dbErr != nil {
				utils.LogToStdError("gocas", dbErr)
				continue
			}

			var ar AuthenticationResponse

			dbErr = json.Unmarshal([]byte(ts.Data), &ar)

			if dbErr != nil {
				utils.LogToStdError("gocas", dbErr)
				continue
			}

			ts.AuthenticationResponse = ar

			if glog.V(2) {
				glog.Info("Session AuthenticationResponse user: ", string(ar.User))
			}

			ticketStores = append(ticketStores, &ts)
		}
	}

	sql := `SELECT * FROM tickets 
			WHERE t_id= ?;`

	s.DB.GetRows(parseRows, sql, id)

	if dbErr != nil {
		return nil, dbErr
	}

	if len(ticketStores) == 0 { //nothing in the database, give up
		return nil, ErrInvalidTicket
	}

	//Just grab the first result from the DB having this ID
	t := ticketStores[0]

	if glog.V(2) {
		glog.Info("Ticket used: ", string(t.ID))
	}

	s.mu.RUnlock()

	if t == nil {
		return nil, ErrInvalidTicket
	}

	return &t.AuthenticationResponse, nil
}

// Write stores the AuthenticationResponse for a ticket
func (s *MySQLStore) Write(id string, ticket *AuthenticationResponse) error {

	s.mu.Lock()

	jsonTicket, err := json.Marshal(ticket)

	if err != nil {
		return err
	}

	now := database.GetNullTime(time.Now(), time.UTC)

	ts := MySQLTicketStore{
		ID:      id,
		Data:    string(jsonTicket),
		Updated: now,
		Created: now,
	}

	sql := `INSERT INTO tickets (t_id, t_data, t_created, t_updated) 
			VALUES (:t_id, :t_data, :t_created, :t_updated)`

	_, err = s.DB.ExecNamed(sql, ts)

	if err != nil {
		return err
	}

	s.mu.Unlock()
	return nil
}

// Delete removes the AuthenticationResponse for a ticket
func (s *MySQLStore) Delete(id string) error {

	s.mu.Lock()

	if len(id) > 64 {
		return fmt.Errorf("failed to delete ticket; ID not formatted properly")
	}

	sql := fmt.Sprintf(`DELETE FROM tickets WHERE t_id = '%s';`, id)
	_, err := s.DB.ExecSingle(sql)

	if err != nil {
		return err
	}

	s.mu.Unlock()
	return nil
}

// Clear removes all ticket data
func (s *MySQLStore) Clear() error {

	s.mu.Lock()
	sql := `TRUNCATE TABLE tickets;`

	_, err := s.DB.ExecSingle(sql)
	if err != nil {
		return err
	}

	s.mu.Unlock()
	return nil
}

func setAuthenticationResponseFromMySQL(c *Client, cookie *http.Cookie, w http.ResponseWriter, r *http.Request) error {

	if glog.V(2) {
		glog.Infof("gocas: getting ticket from MySQL (cookie %v)", cookie.Value)
	}

	ticket, err := getTicketFromMySQL(c.db, cookie)

	if err != nil {
		return err
	}

	if glog.V(2) {
		glog.Infof("gocas: ticket from MySQL was %v", ticket)
	}

	t, err := c.tickets.Read(ticket)

	if err != nil {
		return err
	}

	if t == nil {
		return fmt.Errorf("could not read ticket %s in AuthenicationResponse", ticket)
	}

	setAuthenticationResponse(r, t)
	return nil

}

func setAuthenticationResponseFromCookie(c *Client, cookie *http.Cookie, w http.ResponseWriter, r *http.Request) error {
	var err error

	sessionValue, err := c.sessions.Read(cookie.Value)

	if err != nil {
		return err
	}

	if sessionValue != "" {

		var t *AuthenticationResponse

		t, err = c.tickets.Read(sessionValue)

		if err == nil {
			setAuthenticationResponse(r, t)
			return nil
		}

		clearCookie(w, cookie)
		return err
	}

	return fmt.Errorf("session not in cookie")
}

func setAuthenticationResponseFromURL(c *Client, cookie *http.Cookie, w http.ResponseWriter, r *http.Request) error {
	var err error

	//3) Get from URL (usually the first login)
	if ticket := r.URL.Query().Get("ticket"); ticket != "" {

		if err = c.validateTicket(ticket, r); err != nil {
			return err // allow ServeHTTP()
		}

		err = c.SetSession(cookie.Value, ticket)

		t, err := c.tickets.Read(ticket)
		if err == nil {
			setAuthenticationResponse(r, t)

			if c.runOnLogin != nil {
				c.runOnLogin.Run(Username(r))
			}

			http.Redirect(w, r, removeTicketFromURL(r.URL).String(), 302)

			return nil
		}

		clearCookie(w, cookie)

		return err
	}

	return fmt.Errorf("ticket was blank")
}

func removeTicketFromURL(myURL *url.URL) *url.URL {

	q := myURL.Query()
	q.Del("ticket")

	myURL.RawQuery = q.Encode()

	return myURL
}
