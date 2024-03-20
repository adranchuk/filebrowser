package auth

import (
	"context"
	"net/http"
	"net/url"

	gost "github.com/bldsoft/gost/auth/jwt"
	"github.com/bldsoft/gost/mongo"
	"github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
	"github.com/go-chi/jwtauth"
)

const (
	collectionName = "filebrowser_session"
)

const MethodSession settings.AuthMethod = "session"

type SessionAuth struct {
	*gost.JwtConfig
	mongo.Config
}

func (a SessionAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (u *users.User, err error) {
	defer func() {
		if err != nil && u == nil {
			u, err = JSONAuth{nil}.Auth(r, usr, stg, srv)
		}
	}()

	if err := connect(a.Config); err != nil {
		return nil, err
	}

	if err := a.JwtConfig.Validate(); err != nil {
		return nil, err
	}

	key := a.getToken(r)
	if err != nil {
		return nil, err
	}

	ctx := r.Context()

	rawTkn, err := currStorage.get(ctx, key)
	if err != nil {
		return nil, err
	}

	_ = currStorage.delete(ctx, key)

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

func (a SessionAuth) LoginPage() bool {
	return false
}

func (a SessionAuth) getToken(r *http.Request) string {
	if refererer := r.Header.Get("Referer"); refererer != "" {
		u, _ := url.Parse(refererer)
		return u.Query().Get("token")
	}

	return r.URL.Query().Get("token")
}

var currStorage = &mongoStorage{}

type mongoStorage struct {
	mongo.Config
	rep mongo.Repository[session, *session]
}

func (s *mongoStorage) get(ctx context.Context, key string) (string, error) {
	res, err := s.rep.FindByID(ctx, key)
	if err != nil {
		return "", err
	}

	return res.JWT, nil
}

func (s *mongoStorage) delete(ctx context.Context, key string) error {
	return s.rep.Delete(ctx, key)
}

func connect(config mongo.Config) error {
	if config.Server == currStorage.Server && config.DbName == currStorage.DbName {
		return nil
	}

	if err := config.Validate(); err != nil {
		return err
	}

	storage := mongo.NewStorage(config)
	storage.Connect()
	rep := mongo.NewRepository[session](storage, collectionName)

	currStorage = &mongoStorage{
		config, rep,
	}
	return nil
}

type session struct {
	mongo.EntityID
	JWT string `bson:"jwt"`
}
