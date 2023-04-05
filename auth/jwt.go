package auth

import (
	"fmt"
	"net/http"

	gost "github.com/bldsoft/gost/auth/jwt"
	"github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
	"github.com/go-chi/jwtauth"
)

const MethodJWTAuth settings.AuthMethod = "jwt"

const (
	roleAdmin      = "admin"
	roleSuperAdmin = "superadmin"
)

type JWTAuth struct {
	*gost.JwtConfig
}

func (a JWTAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (*users.User, error) {
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

	fmt.Println(claims)
	if claims["email"] == nil || claims["path"] == nil {
		return nil, errors.ErrInvalidRequestParams
	}

	perms := users.Permissions{
		Download: true,
		Execute:  true,
	}
	if role := claims["role"]; role != nil {
		if role.(string) == roleAdmin || role.(string) == roleSuperAdmin {
			perms.Admin = true
		}
	}

	u := &users.User{
		ID:       1,
		Username: claims["email"].(string),
		Scope:    claims["path"].(string),
		Perm:     perms,
	}

	// u, err = usr.Get(srv.Root, "admin")
	// if err != nil {
	// 	return nil, err
	// }

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

	cookie, err := r.Cookie("x-auth")
	if err != nil || cookie.Value == "" {
		return "", fmt.Errorf("%w %v", errors.ErrEmptyKey, err)
	}

	return cookie.Value, nil
}
