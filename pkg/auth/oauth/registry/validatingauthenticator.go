package registry

import (
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/openshift/origin/pkg/auth/authenticator"
	"github.com/openshift/origin/pkg/oauth/apis/oauth"
)

type oauthTokenValidatingAuthenticator struct {
	delegate  authenticator.OAuthToken
	validator authenticator.OAuthTokenValidator
}

func NewValidatingOAuthTokenAuthenticator(delegate authenticator.OAuthToken, validators ...authenticator.OAuthTokenValidator) authenticator.OAuthToken {
	return &oauthTokenValidatingAuthenticator{
		delegate:  delegate,
		validator: authenticator.OAuthTokenValidators(validators),
	}
}

func (a *oauthTokenValidatingAuthenticator) AuthenticateOAuthToken(name string) (*oauth.OAuthAccessToken, user.Info, bool, error) {
	token, user, ok, err := a.delegate.AuthenticateOAuthToken(name)
	if !ok || err != nil {
		return token, user, ok, err
	}

	if err := a.validator.Validate(token); err != nil {
		return nil, nil, false, err
	}

	return token, user, ok, err
}
