package authenticator

import (
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/openshift/origin/pkg/auth/api"
	"github.com/openshift/origin/pkg/oauth/apis/oauth"
)

type Assertion interface {
	AuthenticateAssertion(assertionType, data string) (user.Info, bool, error)
}

type Client interface {
	AuthenticateClient(client api.Client) (user.Info, bool, error)
}

type OAuthToken interface {
	AuthenticateOAuthToken(token string) (*oauth.OAuthAccessToken, user.Info, bool, error)
}

var _ authenticator.Token = OAuthTokenAdapterFunc(nil)

type OAuthTokenAdapterFunc func(token string) (*oauth.OAuthAccessToken, user.Info, bool, error)

func (f OAuthTokenAdapterFunc) AuthenticateToken(token string) (user.Info, bool, error) {
	_, user, ok, err := f(token)
	return user, ok, err
}

type OAuthTokenValidator interface {
	Validate(token *oauth.OAuthAccessToken) error
}

var _ OAuthTokenValidator = OAuthTokenValidators(nil)

type OAuthTokenValidators []OAuthTokenValidator

func (v OAuthTokenValidators) Validate(token *oauth.OAuthAccessToken) error {
	for _, validator := range v {
		if err := validator.Validate(token); err != nil {
			return err
		}
	}
	return nil
}
