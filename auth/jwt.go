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

type JWTAuth struct {
	*gost.JwtConfig
}

func (a JWTAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (*users.User, error) {
	fmt.Println("auth jwt")
	if err := a.Validate(); err != nil {
		fmt.Println("validate err: ", err)
		return nil, err
	}

	rawTkn, err := a.getToken(r)
	if err != nil {
		fmt.Println("failed to get token: ", err)
		return nil, err
	}

	ja := jwtauth.New(a.Alg, a.PublicKey(), nil)
	token, err := jwtauth.VerifyToken(ja, rawTkn)
	if err != nil {
		fmt.Println("failed to verify token: ", err)
		return nil, err
	}

	claims, err := token.AsMap(r.Context())
	if err != nil {
		fmt.Println("failed to get token as map: ", err)
		return nil, err
	}

	if claims["username"] == nil {
		fmt.Println("empty username: ", err)
		return nil, errors.ErrInvalidRequestParams
	}

	u, err := usr.Get(srv.Root, claims["username"].(string))
	if err != nil {
		fmt.Println("failed to get user from claims: ", err)
		return nil, err
	}

	fmt.Printf("jwt auth: %+v; claims: %v\n", u, claims)
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
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	cookie, err = r.Cookie("auth")
	if err != nil || cookie.Value == "" {
		return cookie.Value, nil
	}

	if token = r.URL.Query().Get("token"); token != "" {
		return token, nil
	}

	return cookie.Value, errors.ErrEmptyKey
}
