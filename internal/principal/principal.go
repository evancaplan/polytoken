package principal

import "time"

type Principal struct {
	Sub       string
	Iss       string
	Scopes    []string
	Roles     []string
	IssuedAt  time.Time
	expiresAt time.Time
	claims    map[string]interface{}
}
