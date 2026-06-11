package principal

import "time"

type Principal struct {
	Sub       string
	Iss       string
	Scopes    []string
	Roles     []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Claims    map[string]interface{}
}
