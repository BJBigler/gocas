package gocas

import (
	"fmt"
	"time"

	"github.com/bjbigler/database"
	"github.com/bjbigler/princeton-seminars/utils"
	"github.com/jmoiron/sqlx"
)

//Used to set and retrive session data when MySQL session storage is desired or required.

//Session ...
type Session struct {
	ID      string            `db:"s_key"`
	Value   string            `db:"s_value"`
	Created database.NullTime `db:"s_created"`
	Updated database.NullTime `db:"s_updated"`
}

// setSession stores the session id to ticket mapping in the Client.
func setSessionInMySQL(db *database.DB, id string, ticket string) (*Session, error) {

	//utils.Log("Set session with ticket: " + ticket)

	now := database.NullTime{
		Valid: true,
		Time:  time.Now(),
	}

	session := Session{
		ID:      id,
		Value:   ticket,
		Updated: now,
	}

	sql := `INSERT INTO sessions (s_key, s_value, s_updated) VALUES (:s_key,:s_value,:s_updated) 
						ON DUPLICATE KEY UPDATE s_value=VALUES(s_value);`

	_, err := db.ExecNamed(sql, session)

	if err != nil {
		return nil, err
	}

	return getSessionFromMySQL(db, id)

}

//GetSession ...
func getSessionFromMySQL(db *database.DB, id string) (*Session, error) {

	sessions := []*Session{}

	var dbErr error
	parseRows := func(rows *sqlx.Rows) {
		for rows.Next() {
			var s Session
			dbErr = rows.StructScan(&s)

			if dbErr != nil {
				utils.LogToStdError("gocas", dbErr)
				continue
			}

			if dbErr != nil {
				utils.LogToStdError("gocas", dbErr)
				continue
			}

			sessions = append(sessions, &s)
		}
	}

	sql := `SELECT * FROM sessions 
			WHERE s_key = ?;`

	db.GetRows(parseRows, sql, id)

	if dbErr != nil {
		return nil, dbErr
	}

	if len(sessions) > 0 {
		return sessions[0], nil
	}

	return nil, fmt.Errorf("session record does not exist (key: %s)", id)
}

//DeleteSession ...
func deleteSessionInMySQL(db *database.DB, id string) error {
	sql := fmt.Sprintf(`DELETE FROM sessions 
						WHERE s_key = ?;`)

	_, err := db.ExecSingle(sql, id)
	return err
}

//ExpireSessions ...
func expireSessionsInMySQL(db *database.DB, ageBefore time.Time) error {
	sql := fmt.Sprintf(`DELETE FROM sessions 
						WHERE s_created <= '%s';`, ageBefore.Format("2006-01-02 15:04:05"))

	_, err := db.ExecSingle(sql)

	return err

}

func deleteSessionFromTicketInMySQL(db *database.DB, ticket string) error {
	sql := fmt.Sprintf(`DELETE FROM sessions
						WHERE s_value LIKE '%s%%';`, ticket)

	_, err := db.ExecSingle(sql)
	return err
}
