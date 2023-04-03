package auth

import (
	"net/http"
	"os"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

const MethodCookieAuth settings.AuthMethod = "cookie"

type CookieAuth struct{}

func (c CookieAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (*users.User, error) {
	cookie, err := r.Cookie("x-auth")
	if err != nil {
		return nil, os.ErrPermission
	}

	u, err := usr.Get(srv.Root, cookie)
	if err != nil {
		return nil, os.ErrPermission
	}

	return u, nil
}

func (c CookieAuth) LoginPage() bool {
	return false
}
