package gocas

// RunOnLogin provides an interface for running a function post login.
type RunOnLogin interface {
	//Run passes the netid back to the function
	Run(netid string) error
}
