package gocas

import (
	"net/url"
	"strings"
)

var (
	urlCleanParameters = []string{"gateway", "renew", "service", "ticket"}
)

// sanitisedURL cleans a URL of CAS specific parameters
func sanitisedURL(unclean *url.URL) *url.URL {

	q := unclean.Query()

	for _, param := range urlCleanParameters {
		q.Del(param)
	}

	unclean.RawQuery = q.Encode()

	return unclean
}

// sanitisedURLString cleans a URL and returns its string value
func sanitisedURLString(unclean *url.URL, requiresTrailingSlash bool) string {

	result := sanitisedURL(unclean).String()
	result = strings.TrimSuffix(result, "/")
	if requiresTrailingSlash {
		//Check if path already has a slash at the end of it
		//e.g., https://seminars.columbia.edu/someresource -- OK
		//but https://seminars.columbia.edu -- not OK and needs a slash
		parsedService, err := url.Parse(result)
		if err == nil {
			if parsedService != nil && (parsedService.Path == "/" || parsedService.Path == "") {
				result += "/"
			}
		}

	}

	return result
}
