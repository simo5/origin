package registry

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/google/btree"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/clock"

	"github.com/openshift/origin/pkg/auth/authenticator"
	"github.com/openshift/origin/pkg/oauth/apis/oauth"
	"github.com/openshift/origin/pkg/oauth/apis/oauth/validation"
)

var ErrTimedout = errors.New("Token timed out")

const timeoutsInPatch = `[{"op": "test", "path": "/timeoutsIn", "value": %d}, {"op": "replace", "path": "/timeoutsIn", "value": %d}]`

var _ btree.Item = &tokenData{}

type tokenData struct {
	token *oauth.OAuthAccessToken
	seen  time.Time
}

func (a *tokenData) timeout() time.Time {
	return a.token.CreationTimestamp.Add(time.Duration(a.token.TimeoutsIn) * time.Second)
}

func (a *tokenData) Less(than btree.Item) bool {
	other := than.(*tokenData)

	// From the btree.Item docs:
	// > If !a.Less(b) && !b.Less(a), we treat this to mean a == b (i.e. we can only hold one of either a or b in the tree)
	// Thus we use this to guarantee that the btree will not contain duplicate entries for the same token
	if a.token.Name == other.token.Name {
		return false
	}

	selfTimeout := a.timeout()
	otherTimeout := other.timeout()

	if selfTimeout.Equal(otherTimeout) {
		return a.token.Name < other.token.Name
	}

	return selfTimeout.Before(otherTimeout)
}

type oauthTokenTimeoutValidator struct {
	oauthClient    OAuthClientGetter
	tokens         OAuthAccessTokenPatcher
	tokenChannel   chan *tokenData
	tree           *btree.BTree
	defaultTimeout time.Duration
	flushTimeout   time.Duration
	safetyMargin   time.Duration
	clock          clock.Clock // for testing
}

type OAuthClientGetter interface {
	Get(name string) (*oauth.OAuthClient, error)
}

type OAuthAccessTokenPatcher interface {
	Patch(name string, pt ktypes.PatchType, data []byte, subresources ...string) (*oauth.OAuthAccessToken, error)
}

func NewOAuthTokenTimeoutValidator(tokens OAuthAccessTokenPatcher, oauthClient OAuthClientGetter, defaultTimeout int32) (authenticator.OAuthTokenValidator, func(stopCh <-chan struct{})) {
	return newOAuthTokenTimeoutValidator(tokens, oauthClient, defaultTimeout, clock.RealClock{})
}

func newOAuthTokenTimeoutValidator(tokens OAuthAccessTokenPatcher, oauthClient OAuthClientGetter, defaultTimeout int32, clock clock.Clock) (authenticator.OAuthTokenValidator, func(stopCh <-chan struct{})) {
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
		tokenChannel: make(chan *tokenData),
		// FIXME: what is the right degree for the btree
		tree:           btree.New(32),
		defaultTimeout: timeoutAsDuration(defaultTimeout),
		flushTimeout:   timeoutAsDuration(flushTimeout),
		safetyMargin:   timeoutAsDuration(safetyMargin),
		clock:          clock,
	}
	glog.V(5).Infof("Timeout validator set to use defaultTimeout=%s flushTimeout=%s", timeoutValidator.defaultTimeout, timeoutValidator.flushTimeout)
	return timeoutValidator, timeoutValidator.run
}

// Validate is called with a token when it is seen by an authenticator
// it touches only the tokenChannel so it is safe to call from other threads
func (a *oauthTokenTimeoutValidator) Validate(token *oauth.OAuthAccessToken) error {
	now := a.clock.Now()
	td := &tokenData{
		token: token,
		seen:  now,
	}

	// We only need to check the token's timeout if the value is not 0 (meaning never timeout)
	// However, we always need to update that we saw the token so that:
	// 1. Adding a timeout to OAuth client will cause its older tokens to start having timeouts
	// 2. Removing a timeout from an OAuth client will cause its older tokens to stop having timeouts
	if token.TimeoutsIn > 0 && td.timeout().Before(now) {
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

func (a *oauthTokenTimeoutValidator) updateTokenSeen(td *tokenData) {
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
		glog.V(5).Infof("Updating flush timeout from %s to %d seconds", a.flushTimeout, timeout)
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

func (a *oauthTokenTimeoutValidator) flush(flushHorizon time.Time) {
	flushedTokens := 0
	totalTokens := a.tree.Len()
	var failedPatches []*tokenData

	glog.V(5).Infof("Flushing tokens timing out before %s", flushHorizon)

	for item := a.tree.Min(); item != nil; item = a.tree.Min() {
		td := item.(*tokenData)
		if td.timeout().After(flushHorizon) {
			// out of items within the flush Horizon
			break
		}

		// remove item from tree regardless of if we succeed with the patch
		a.tree.DeleteMin()

		// calculate new timeout for this token
		// timeout = CreationTimestamp + TimeoutsIn
		// new TimeoutsIn = seen - CreationTimestamp + AccessTokenTimeoutSeconds
		delta := a.clientTimeout(td.token.ClientName)

		// the one special case is if delta is 0, meaning the OAuth client has 0 as its AccessTokenTimeoutSeconds
		// if that happens, we set TimeoutsIn to 0 to indicate this token should no longer timeout
		var newTimeout int32
		if delta > 0 {
			newTimeout = int32((td.seen.Sub(td.token.CreationTimestamp.Time) + delta) / time.Second)
		}

		patch := []byte(fmt.Sprintf(timeoutsInPatch, td.token.TimeoutsIn, newTimeout))
		_, err := a.tokens.Patch(td.token.Name, ktypes.JSONPatchType, patch)
		if err != nil {
			// we should only retry if the error may be transient
			// TODO determine if we should bother retrying at all
			// TODO if we do decide to retry, maybe we should use one of the exponential backoff helpers here instead of adding back to the tree
			if kerrors.IsConflict(err) || kerrors.IsServerTimeout(err) {
				failedPatches = append(failedPatches, td)
			}
			glog.V(5).Infof("Token timeout for user=%q client=%q scopes=%v was not updated: %v",
				td.token.UserName, td.token.ClientName, td.token.Scopes, err)
		} else {
			flushedTokens++
			glog.V(5).Infof("Updated token timeout for user=%q client=%q scopes=%v creation=%s from %d to %d",
				td.token.UserName, td.token.ClientName, td.token.Scopes, td.token.CreationTimestamp, td.token.TimeoutsIn, newTimeout)
		}
	}

	if retry := len(failedPatches); retry > 0 {
		glog.V(5).Infof("Re-adding %d failed patches", retry)
	}
	// add the failed attempts back so we can try them the next time we flush
	for _, failedPatch := range failedPatches {
		a.tree.ReplaceOrInsert(failedPatch)
	}

	glog.V(5).Infof("Flushed %d tokens out of %d in bucket", flushedTokens, totalTokens)
}

func (a *oauthTokenTimeoutValidator) run(stopCh <-chan struct{}) {
	glog.V(5).Infof("Started Token Timeout Flush Handling thread!")

	nextTimer := a.clock.NewTimer(a.flushTimeout)
	nextTimeout := a.clock.Now().Add(a.flushTimeout)

	updateTimerAndFlush := func() {
		nextTimer = a.clock.NewTimer(a.flushTimeout)
		nextTimeout = a.clock.Now().Add(a.flushTimeout)
		a.flush(nextTimeout.Add(a.safetyMargin))
	}

	closeTimer := func() {
		// stop regular timer, consume channel if already fired
		if !nextTimer.Stop() {
			<-nextTimer.C()
		}
	}
	defer closeTimer()

	for {
		select {
		case <-stopCh:
			// if channel closes, terminate
			return

		case td := <-a.tokenChannel:
			a.tree.ReplaceOrInsert(td)
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

		case <-nextTimer.C():
			updateTimerAndFlush()
		}
	}
}
