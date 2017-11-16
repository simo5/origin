package registry

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/google/btree"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/openshift/origin/pkg/auth/authenticator"
	"github.com/openshift/origin/pkg/oauth/apis/oauth"
	"github.com/openshift/origin/pkg/oauth/apis/oauth/validation"
)

var ErrTimedout = errors.New("Token timed out")

const timeoutsInPatch = `[{"op": "test", "path": "/timeoutsIn", "value": %d}, {"op": "replace", "path": "/timeoutsIn", "value": %d}]`

type tokenData struct {
	token *oauth.OAuthAccessToken
	seen  time.Time
}

func (a *tokenData) timeout() time.Time {
	return a.token.CreationTimestamp.Time.Add(time.Duration(a.token.TimeoutsIn) * time.Second)
}

type tokenDataRef struct {
	name    string
	timeout time.Time
}

func (a *tokenDataRef) Less(than btree.Item) bool {
	tdr := than.(*tokenDataRef)
	if a.timeout.Equal(tdr.timeout) {
		return a.name < tdr.name
	}
	return a.timeout.Before(tdr.timeout)
}

type oauthTokenTimeoutValidator struct {
	oauthClient    OAuthClientGetter
	tokens         OAuthAccessTokenPatcher
	tokenChannel   chan tokenData
	data           map[string]tokenData
	tree           *btree.BTree
	defaultTimeout time.Duration
	flushTimeout   time.Duration
	safetyMargin   time.Duration
}

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

type OAuthClientGetter interface {
	Get(name string) (*oauth.OAuthClient, error)
}

type OAuthAccessTokenPatcher interface {
	Patch(name string, pt ktypes.PatchType, data []byte, subresources ...string) (*oauth.OAuthAccessToken, error)
}

func NewOAuthTokenTimeoutValidator(tokens OAuthAccessTokenPatcher, oauthClient OAuthClientGetter, defaultTimeout int32) (authenticator.OAuthTokenValidator, func(stopCh <-chan struct{})) {
	// flushTimeout is set to one third of defaultTimeout
	flushTimeout := defaultTimeout / 3
	if flushTimeout < validation.MinFlushTimeout {
		flushTimeout = validation.MinFlushTimeout
	}
	// safetyMargin is set to one tenth of flushTimeout
	safetyMargin := flushTimeout / 10
	timeoutValidator := &oauthTokenTimeoutValidator{
		oauthClient:  oauthClient,
		tokens:       tokens,
		tokenChannel: make(chan tokenData),
		data:         make(map[string]tokenData),
		// FIXME: what is the right degree for the btree
		tree:           btree.New(32),
		defaultTimeout: timeoutAsDuration(defaultTimeout),
		flushTimeout:   timeoutAsDuration(flushTimeout),
		safetyMargin:   timeoutAsDuration(safetyMargin),
	}
	glog.V(5).Infof("Timeout validator set to use defaultTimeout=%s flushTimeout=%s", timeoutValidator.defaultTimeout, timeoutValidator.flushTimeout)
	return timeoutValidator, timeoutValidator.run
}

// Validate is called with a token when it is seen by an authenticator
// it touches only the tokenChannel so it is safe to call from other threads
func (a *oauthTokenTimeoutValidator) Validate(token *oauth.OAuthAccessToken) error {
	if token.TimeoutsIn == 0 {
		return nil
	}

	now := time.Now()
	td := tokenData{
		token: token,
		seen:  now,
	}
	if td.timeout().Before(now) {
		return ErrTimedout
	}

	// After a positive timeout check we need to update the timeout and
	// schedule an update so that we can either set or update the Timeout
	// we launch a short lived goroutine to avoid blocking
	go a.updateTokenSeen(td)

	return nil
}

func timeoutAsDuration(timeout int32) time.Duration {
	return time.Duration(timeout) * time.Second
}

func (a *oauthTokenTimeoutValidator) updateTokenSeen(td tokenData) {
	a.tokenChannel <- td
}

func (a *oauthTokenTimeoutValidator) updateTimeouts(clientTimeout int32) {
	// timeout is set to one third of clientTimeout
	timeout := clientTimeout / 3
	flushTimeout := int32(a.flushTimeout / time.Second)
	if timeout < flushTimeout {
		if timeout < validation.MinFlushTimeout {
			timeout = validation.MinFlushTimeout
		}
		glog.V(5).Infof("Updating flush timeout to %s", timeout)
		a.flushTimeout = timeoutAsDuration(timeout)
		// safetyMargin is set to one tenth of flushTimeout
		a.safetyMargin = timeoutAsDuration(timeout / 10)
	}
}

func (a *oauthTokenTimeoutValidator) clientTimeout(name string) time.Duration {
	oauthClient, err := a.oauthClient.Get(name)
	if err != nil {
		glog.V(5).Infof("Failed to fetch OAuthClient %q for timeout value: %v, using default timeout %s", name, err, a.defaultTimeout)
		return a.defaultTimeout
	}
	if oauthClient.AccessTokenTimeoutSeconds == nil {
		glog.V(5).Infof("Using default timeout of %s for OAuth client %q", a.defaultTimeout, oauthClient.Name)
		return a.defaultTimeout
	}
	glog.V(5).Infof("OAuth client %q set to use %d seconds as timeout", oauthClient.Name, *oauthClient.AccessTokenTimeoutSeconds)
	a.updateTimeouts(*oauthClient.AccessTokenTimeoutSeconds)
	return timeoutAsDuration(*oauthClient.AccessTokenTimeoutSeconds)
}

func (a *oauthTokenTimeoutValidator) insert(td tokenData) {
	a.data[td.token.Name] = td
	a.tree.ReplaceOrInsert(&tokenDataRef{td.token.Name, td.timeout()})
}

func (a *oauthTokenTimeoutValidator) remove(td tokenData, tdr *tokenDataRef) {
	a.tree.Delete(tdr)
	delete(a.data, td.token.Name)
}

func (a *oauthTokenTimeoutValidator) flush(flushHorizon time.Time) {
	flushedTokens := 0
	totalTokens := len(a.data)
	var failedPatches []tokenData

	glog.V(5).Infof("Flushing tokens timing out before %s", flushHorizon)

	for item := a.tree.Min(); item != nil; item = a.tree.Min() {
		tdr := item.(*tokenDataRef)
		if tdr.timeout.After(flushHorizon) {
			// out of items within the flush Horizon
			break
		}

		td := a.data[tdr.name]
		delta := a.clientTimeout(td.token.ClientName)
		newTimeout := int32((td.seen.Sub(td.token.CreationTimestamp.Time) + delta) / time.Second)

		patch := []byte(fmt.Sprintf(timeoutsInPatch, td.token.TimeoutsIn, newTimeout))
		_, err := a.tokens.Patch(td.token.Name, ktypes.JSONPatchType, patch)
		if err != nil {
			// if the token has been deleted, we should not retry
			if !kerrors.IsNotFound(err) {
				failedPatches = append(failedPatches, td)
			}
			glog.V(5).Infof("Token timeout for user=%q client=%q scopes=%v was not updated: %v",
				td.token.UserName, td.token.ClientName, td.token.Scopes, err)
		} else {
			flushedTokens++
			glog.V(5).Infof("Updated token timeout for user=%q client=%q scopes=%v creation=%s from %d to %d",
				td.token.UserName, td.token.ClientName, td.token.Scopes, td.token.CreationTimestamp.Time, td.token.TimeoutsIn, newTimeout)
		}

		a.remove(td, tdr)
	}

	if retry := len(failedPatches); retry > 0 {
		glog.V(5).Infof("Re-adding %d failed patches", retry)
	}
	// add the failed attempts back so we can try them the next time we flush
	for _, failedPatch := range failedPatches {
		a.insert(failedPatch)
	}

	glog.V(5).Infof("Flushed %d tokens out of %d in bucket", flushedTokens, totalTokens)
}

func (a *oauthTokenTimeoutValidator) run(stopCh <-chan struct{}) {
	glog.V(5).Infof("Started Token Timeout Flush Handling thread!")

	nextTimer := time.NewTimer(a.flushTimeout)
	nextTimeout := time.Now().Add(a.flushTimeout)

	updateTimerAndFlush := func() {
		nextTimer = time.NewTimer(a.flushTimeout)
		nextTimeout = time.Now().Add(a.flushTimeout)
		a.flush(nextTimeout.Add(a.safetyMargin))
	}

	closeTimer := func() {
		// stop regular timer, consume channel if already fired
		if !nextTimer.Stop() {
			<-nextTimer.C
		}
	}
	defer closeTimer()

	for {
		select {
		case <-stopCh:
			// if channel closes, terminate
			return

		case td := <-a.tokenChannel:
			a.insert(td)
			// if this token is going to time out before the timer, fire
			// immediately (safety margin is added to avoid racing too close)
			tokenTimeout := td.timeout()
			safetyTimeout := nextTimeout.Add(a.safetyMargin)
			if safetyTimeout.After(tokenTimeout) {
				glog.V(5).Infof("Timeout for user=%q client=%q scopes=%v falls below safety margin (%s < %s) forcing flush",
					td.token.UserName, td.token.ClientName, td.token.Scopes, tokenTimeout, safetyTimeout)
				closeTimer()
				updateTimerAndFlush()
			}

		case <-nextTimer.C:
			updateTimerAndFlush()
		}
	}
}
