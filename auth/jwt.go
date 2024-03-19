package auth

import (
	"net/http"
	"net/url"

	gost "github.com/bldsoft/gost/auth/jwt"
	"github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
	"github.com/go-chi/jwtauth"
)

const MethodJWTAuth settings.AuthMethod = "jwt"

type JWTAuth struct {
	*gost.JwtConfig
}

func (a JWTAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (u *users.User, err error) {
	defer func() {
		if err != nil && u == nil {
			u, err = JSONAuth{nil}.Auth(r, usr, stg, srv)
		}
	}()

	if err := a.Validate(); err != nil {
		return nil, err
	}

	rawTkn, err := a.getToken(r)
	if err != nil {
		return nil, err
	}

	ja := jwtauth.New(a.Alg, a.PublicKey(), nil)
	token, err := jwtauth.VerifyToken(ja, rawTkn)
	if err != nil {
		return nil, err
	}

	claims, err := token.AsMap(r.Context())
	if err != nil {
		return nil, err
	}

	if claims["username"] == nil {
		return nil, errors.ErrInvalidRequestParams
	}

	u, err = usr.Get(srv.Root, claims["username"].(string))
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (a JWTAuth) LoginPage() bool {
	return false
}

func (a JWTAuth) getToken(r *http.Request) (string, error) {
	token := r.Header.Get("X-AUTH")
	if token != "" {
		return token, nil
	}

	if refererer := r.Header.Get("Referer"); refererer != "" {
		u, _ := url.Parse(refererer)
		return u.Query().Get("token"), nil
	}

	if token = r.URL.Query().Get("token"); token != "" {
		return token, nil
	}

	cookie, err := r.Cookie("x-auth")
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	cookie, err = r.Cookie("auth")
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	return "", errors.ErrEmptyKey
}
