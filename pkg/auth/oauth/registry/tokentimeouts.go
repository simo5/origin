package registry

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/golang/glog"
	"github.com/google/btree"

	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/openshift/origin/pkg/auth/authenticator"
	"github.com/openshift/origin/pkg/oauth/apis/oauth"
	"github.com/openshift/origin/pkg/oauth/apis/oauth/validation"
	oauthclient "github.com/openshift/origin/pkg/oauth/generated/internalclientset/typed/oauth/internalversion"
	oauthlister "github.com/openshift/origin/pkg/oauth/generated/listers/oauth/internalversion"
)

var ErrTimedout = errors.New("Token timed out")

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
	if a.timeout.Equal(than.(*tokenDataRef).timeout) {
		return a.name < than.(*tokenDataRef).name
	}
	return a.timeout.Before(than.(*tokenDataRef).timeout)
}

type oauthTokenTimeoutValidator struct {
	oauthClient    oauthlister.OAuthClientLister
	tokens         oauthclient.OAuthAccessTokenInterface
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

func NewOAuthTokenTimeoutValidator(tokens oauthclient.OAuthAccessTokenInterface, oauthClient oauthlister.OAuthClientLister, defaultTimeout int32) (authenticator.OAuthTokenValidator, func(stopCh <-chan struct{})) {
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
	timeout := int32(math.Ceil(float64(clientTimeout) / 3.0))
	flushTimeout := int32(a.flushTimeout / time.Second)
	if timeout < flushTimeout {
		if timeout < validation.MinFlushTimeout {
			timeout = validation.MinFlushTimeout
		}
		a.flushTimeout = timeoutAsDuration(timeout)
		a.safetyMargin = timeoutAsDuration(timeout / 10)
	}
}

func (a *oauthTokenTimeoutValidator) clientTimeout(name string) time.Duration {
	oauthClient, err := a.oauthClient.Get(name)
	if err != nil {
		glog.V(5).Infof("Failed to fetch OAuthClient for timeout value: %v", err)
		return a.defaultTimeout
	}
	if oauthClient.AccessTokenTimeoutSeconds == nil {
		glog.V(5).Infof("Using default timeout of %d for OAuth client %s", a.defaultTimeout, oauthClient.Name)
		return a.defaultTimeout
	}
	a.updateTimeouts(*oauthClient.AccessTokenTimeoutSeconds)
	return timeoutAsDuration(*oauthClient.AccessTokenTimeoutSeconds)
}

func (a *oauthTokenTimeoutValidator) insert(td tokenData) {
	a.data[td.token.Name] = td
	a.tree.ReplaceOrInsert(&tokenDataRef{td.token.Name, td.timeout()})
}

func (a *oauthTokenTimeoutValidator) remove(td tokenData, tdr *tokenDataRef) {
	if tdr == nil {
		tdr = &tokenDataRef{td.token.Name, td.timeout()}
	}
	a.tree.Delete(tdr)
	delete(a.data, td.token.Name)
}

func (a *oauthTokenTimeoutValidator) flush(flushHorizon time.Time) {
	flushedTokens := 0
	totalTokens := len(a.data)

	glog.V(5).Infof("Flushing tokens timing out before %v", flushHorizon)

	for item := a.tree.Min(); item != nil; item = a.tree.Min() {
		tdr := item.(*tokenDataRef)
		if tdr.timeout.After(flushHorizon) {
			// out of items within the flush Horizon
			break
		}

		td := a.data[tdr.name]
		delta := a.clientTimeout(td.token.ClientName)
		var newtimeout int32
		if delta > 0 {
			newtimeout = int32((td.seen.Sub(td.token.CreationTimestamp.Time) + delta) / time.Second)
		}
		patch := []byte(fmt.Sprintf(`[{"op": "test", "path": "/timeoutsIn", "value": %d}, {"op": "replace", "path": "/timeoutsIn", "value": %d}]`, td.token.TimeoutsIn, newtimeout))
		_, err := a.tokens.Patch(td.token.Name, ktypes.JSONPatchType, patch)
		if err != nil {
			glog.V(5).Infof("Token timeout was not updated: %v", err)
			// TODO can we not remove and try later?
		}
		a.remove(td, tdr)
		flushedTokens++
	}

	glog.V(5).Infof("Flushed %d tokens out of %d in bucket", flushedTokens, totalTokens)
}

func (a *oauthTokenTimeoutValidator) run(stopCh <-chan struct{}) {
	glog.V(5).Infof("Started Token Timeout Flush Handling thread!")

	nextTimer := time.NewTimer(a.flushTimeout)
	nextTimeout := time.Now().Add(a.flushTimeout)

	for {
		select {
		case <-stopCh:
			// stop regular timer, consume channel if already fired
			if !nextTimer.Stop() {
				<-nextTimer.C
			}
			// if channel closes, terminate
			return

		case td := <-a.tokenChannel:
			a.insert(td)
			// if this token is going to time out before the timer, fire
			// immediately (safety margin is added to avoid racing too close)
			tokenTimeout := td.timeout()
			safetyTimeout := nextTimeout.Add(a.safetyMargin)
			if safetyTimeout.After(tokenTimeout) {
				glog.V(5).Infof("Timeout falls below safety margin (%s < %s) forcing flush", tokenTimeout, safetyTimeout)
				// stop regular timer, consume channel if already fired
				if !nextTimer.Stop() {
					<-nextTimer.C
				}
				nextTimer = time.NewTimer(a.flushTimeout)
				nextTimeout = time.Now().Add(a.flushTimeout)
				a.flush(nextTimeout.Add(a.safetyMargin))
			}

		case <-nextTimer.C:
			nextTimer = time.NewTimer(a.flushTimeout)
			nextTimeout = time.Now().Add(a.flushTimeout)
			a.flush(nextTimeout.Add(a.safetyMargin))
		}
	}
}
