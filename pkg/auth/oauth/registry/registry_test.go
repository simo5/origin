package registry

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RangelReale/osin"
	"github.com/RangelReale/osincli"
	"github.com/google/btree"

	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	clienttesting "k8s.io/client-go/testing"

	"github.com/openshift/origin/pkg/auth/api"
	"github.com/openshift/origin/pkg/auth/oauth/handlers"
	"github.com/openshift/origin/pkg/auth/userregistry/identitymapper"
	oapi "github.com/openshift/origin/pkg/oauth/apis/oauth"
	oauthfake "github.com/openshift/origin/pkg/oauth/generated/internalclientset/fake"
	"github.com/openshift/origin/pkg/oauth/server/osinserver"
	"github.com/openshift/origin/pkg/oauth/server/osinserver/registrystorage"
	userapi "github.com/openshift/origin/pkg/user/apis/user"
	usertest "github.com/openshift/origin/pkg/user/registry/test"
)

type testHandlers struct {
	AuthorizeHandler osinserver.AuthorizeHandler

	User         user.Info
	Authenticate bool
	Err          error
	AuthNeed     bool
	AuthErr      error
	GrantNeed    bool
	GrantErr     error

	HandleAuthorizeReq     *osin.AuthorizeRequest
	HandleAuthorizeResp    *osin.Response
	HandleAuthorizeHandled bool
	HandleAuthorizeErr     error

	AuthNeedHandled bool
	AuthNeedErr     error

	GrantNeedGranted bool
	GrantNeedHandled bool
	GrantNeedErr     error

	HandledErr error
}

func (h *testHandlers) HandleAuthorize(ar *osin.AuthorizeRequest, resp *osin.Response, w http.ResponseWriter) (handled bool, err error) {
	h.HandleAuthorizeReq = ar
	h.HandleAuthorizeResp = resp
	h.HandleAuthorizeHandled, h.HandleAuthorizeErr = h.AuthorizeHandler.HandleAuthorize(ar, resp, w)
	return h.HandleAuthorizeHandled, h.HandleAuthorizeErr
}

func (h *testHandlers) AuthenticationNeeded(client api.Client, w http.ResponseWriter, req *http.Request) (bool, error) {
	h.AuthNeed = true
	return h.AuthNeedHandled, h.AuthNeedErr
}

func (h *testHandlers) AuthenticationError(err error, w http.ResponseWriter, req *http.Request) (bool, error) {
	h.AuthErr = err
	return true, nil
}

func (h *testHandlers) AuthenticateRequest(req *http.Request) (user.Info, bool, error) {
	return h.User, h.Authenticate, h.Err
}

func (h *testHandlers) GrantNeeded(user user.Info, grant *api.Grant, w http.ResponseWriter, req *http.Request) (bool, bool, error) {
	h.GrantNeed = true
	return h.GrantNeedGranted, h.GrantNeedHandled, h.GrantNeedErr
}

func (h *testHandlers) GrantError(err error, w http.ResponseWriter, req *http.Request) (bool, error) {
	h.GrantErr = err
	return true, nil
}

func (h *testHandlers) HandleError(err error, w http.ResponseWriter, req *http.Request) {
	h.HandledErr = err
}

func TestRegistryAndServer(t *testing.T) {
	ch := make(chan *http.Request, 1)
	assertServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ch <- req
	}))

	validClient := &oapi.OAuthClient{
		ObjectMeta:   metav1.ObjectMeta{Name: "test"},
		Secret:       "secret",
		RedirectURIs: []string{assertServer.URL + "/assert"},
	}

	restrictedClient := &oapi.OAuthClient{
		ObjectMeta:   metav1.ObjectMeta{Name: "test"},
		Secret:       "secret",
		RedirectURIs: []string{assertServer.URL + "/assert"},
		ScopeRestrictions: []oapi.ScopeRestriction{
			{ExactValues: []string{"user:info"}},
		},
	}

	testCases := map[string]struct {
		Client      *oapi.OAuthClient
		ClientAuth  *oapi.OAuthClientAuthorization
		AuthSuccess bool
		AuthUser    user.Info
		Scope       string
		Check       func(*testHandlers, *http.Request)
	}{
		"needs auth": {
			Client: validClient,
			Check: func(h *testHandlers, _ *http.Request) {
				if !h.AuthNeed || h.GrantNeed || h.AuthErr != nil || h.GrantErr != nil || h.HandleAuthorizeReq.Authorized {
					t.Errorf("expected request to need authentication: %#v", h)
				}
			},
		},
		"needs grant": {
			Client:      validClient,
			AuthSuccess: true,
			AuthUser: &user.DefaultInfo{
				Name: "user",
			},
			Check: func(h *testHandlers, _ *http.Request) {
				if h.AuthNeed || !h.GrantNeed || h.AuthErr != nil || h.GrantErr != nil || h.HandleAuthorizeReq.Authorized {
					t.Errorf("expected request to need to grant access: %#v", h)
				}
			},
		},
		"invalid scope": {
			Client:      validClient,
			AuthSuccess: true,
			AuthUser: &user.DefaultInfo{
				Name: "user",
			},
			Scope: "some-scope",
			Check: func(h *testHandlers, _ *http.Request) {
				if h.AuthNeed || h.GrantNeed || h.AuthErr != nil || h.GrantErr != nil || h.HandleAuthorizeReq.Authorized || h.HandleAuthorizeResp.ErrorId != "invalid_scope" {
					t.Errorf("expected invalid_scope error: %#v, %#v, %#v", h, h.HandleAuthorizeReq, h.HandleAuthorizeResp)
				}
			},
		},
		"disallowed scope": {
			Client:      restrictedClient,
			AuthSuccess: true,
			AuthUser: &user.DefaultInfo{
				Name: "user",
			},
			Scope: "user:full",
			Check: func(h *testHandlers, _ *http.Request) {
				if h.AuthNeed || h.GrantNeed || h.AuthErr != nil || h.GrantErr != nil || h.HandleAuthorizeReq.Authorized || h.HandleAuthorizeResp.ErrorId != "access_denied" {
					t.Errorf("expected access_denied error: %#v, %#v, %#v", h, h.HandleAuthorizeReq, h.HandleAuthorizeResp)
				}
			},
		},
		"has non covered grant": {
			Client:      validClient,
			AuthSuccess: true,
			AuthUser: &user.DefaultInfo{
				Name: "user",
			},
			ClientAuth: &oapi.OAuthClientAuthorization{
				ObjectMeta: metav1.ObjectMeta{Name: "user:test"},
				UserName:   "user",
				ClientName: "test",
				Scopes:     []string{"user:info"},
			},
			Scope: "user:info user:check-access",
			Check: func(h *testHandlers, req *http.Request) {
				if h.AuthNeed || !h.GrantNeed || h.AuthErr != nil || h.GrantErr != nil || h.HandleAuthorizeReq.Authorized {
					t.Errorf("expected request to need to grant access because of uncovered scopes: %#v", h)
				}
			},
		},
		"has covered grant": {
			Client:      validClient,
			AuthSuccess: true,
			AuthUser: &user.DefaultInfo{
				Name: "user",
			},
			ClientAuth: &oapi.OAuthClientAuthorization{
				ObjectMeta: metav1.ObjectMeta{Name: "user:test"},
				UserName:   "user",
				ClientName: "test",
				Scopes:     []string{"user:info", "user:check-access"},
			},
			Scope: "user:info user:check-access",
			Check: func(h *testHandlers, req *http.Request) {
				if h.AuthNeed || h.GrantNeed || h.AuthErr != nil || h.GrantErr != nil || !h.HandleAuthorizeReq.Authorized || h.HandleAuthorizeResp.ErrorId != "" {
					t.Errorf("unexpected flow: %#v, %#v, %#v", h, h.HandleAuthorizeReq, h.HandleAuthorizeResp)
				}
			},
		},
		"has auth and grant": {
			Client:      validClient,
			AuthSuccess: true,
			AuthUser: &user.DefaultInfo{
				Name: "user",
			},
			ClientAuth: &oapi.OAuthClientAuthorization{
				ObjectMeta: metav1.ObjectMeta{Name: "user:test"},
				UserName:   "user",
				ClientName: "test",
				Scopes:     []string{"user:full"},
			},
			Check: func(h *testHandlers, req *http.Request) {
				if h.AuthNeed || h.GrantNeed || h.AuthErr != nil || h.GrantErr != nil || !h.HandleAuthorizeReq.Authorized || h.HandleAuthorizeResp.ErrorId != "" {
					t.Errorf("unexpected flow: %#v, %#v, %#v", h, h.HandleAuthorizeReq, h.HandleAuthorizeResp)
					return
				}
				if req == nil {
					t.Errorf("unexpected nil assertion request")
					return
				}
				if code := req.URL.Query().Get("code"); code == "" {
					t.Errorf("expected query param 'code', got: %#v", req)
				}
			},
		},
	}

	for _, testCase := range testCases {
		h := &testHandlers{}
		h.Authenticate = testCase.AuthSuccess
		h.User = testCase.AuthUser
		objs := []runtime.Object{}
		if testCase.Client != nil {
			objs = append(objs, testCase.Client)
		}
		if testCase.ClientAuth != nil {
			objs = append(objs, testCase.ClientAuth)
		}
		fakeOAuthClient := oauthfake.NewSimpleClientset(objs...)
		storage := registrystorage.New(fakeOAuthClient.Oauth().OAuthAccessTokens(), fakeOAuthClient.Oauth().OAuthAuthorizeTokens(), fakeOAuthClient.Oauth().OAuthClients(), NewUserConversion(), nil)
		config := osinserver.NewDefaultServerConfig()

		h.AuthorizeHandler = osinserver.AuthorizeHandlers{
			handlers.NewAuthorizeAuthenticator(
				h,
				h,
				h,
			),
			handlers.NewGrantCheck(
				NewClientAuthorizationGrantChecker(fakeOAuthClient.Oauth().OAuthClientAuthorizations()),
				h,
				h,
			),
		}

		server := osinserver.New(
			config,
			storage,
			h,
			osinserver.AccessHandlers{
				handlers.NewDenyAccessAuthenticator(),
			},
			h,
		)
		mux := http.NewServeMux()
		server.Install(mux, "")
		s := httptest.NewServer(mux)

		oaclientConfig := &osincli.ClientConfig{
			ClientId:     "test",
			ClientSecret: "secret",
			RedirectUrl:  assertServer.URL + "/assert",
			AuthorizeUrl: s.URL + "/authorize",
			TokenUrl:     s.URL + "/token",
			Scope:        testCase.Scope,
		}
		oaclient, err := osincli.NewClient(oaclientConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		aReq := oaclient.NewAuthorizeRequest(osincli.CODE)
		if _, err := http.Get(aReq.GetAuthorizeUrl().String()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var req *http.Request
		select {
		case out := <-ch:
			req = out
		default:
		}

		testCase.Check(h, req)
	}
}

func TestAuthenticateTokenNotFound(t *testing.T) {
	fakeOAuthClient := oauthfake.NewSimpleClientset()
	userRegistry := usertest.NewUserRegistry()
	tokenAuthenticator := NewOAuthTokenAuthenticator(fakeOAuthClient.Oauth().OAuthAccessTokens(), userRegistry, identitymapper.NoopGroupMapper{})

	_, userInfo, found, err := tokenAuthenticator.AuthenticateOAuthToken("token")
	if found {
		t.Error("Found token, but it should be missing!")
	}
	if err == nil {
		t.Error("Expected not found error")
	}
	if !apierrs.IsNotFound(err) {
		t.Error("Expected not found error")
	}
	if userInfo != nil {
		t.Errorf("Unexpected user: %v", userInfo)
	}
}
func TestAuthenticateTokenOtherGetError(t *testing.T) {
	fakeOAuthClient := oauthfake.NewSimpleClientset()
	fakeOAuthClient.PrependReactor("get", "oauthaccesstokens", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, errors.New("get error")
	})
	userRegistry := usertest.NewUserRegistry()
	tokenAuthenticator := NewOAuthTokenAuthenticator(fakeOAuthClient.Oauth().OAuthAccessTokens(), userRegistry, identitymapper.NoopGroupMapper{})

	_, userInfo, found, err := tokenAuthenticator.AuthenticateOAuthToken("token")
	if found {
		t.Error("Found token, but it should be missing!")
	}
	if err == nil {
		t.Error("Expected error is missing!")
	}
	if err.Error() != "get error" {
		t.Errorf("Expected error %v, but got error %v", "get error", err)
	}
	if userInfo != nil {
		t.Errorf("Unexpected user: %v", userInfo)
	}
}
func TestAuthenticateTokenExpired(t *testing.T) {
	fakeOAuthClient := oauthfake.NewSimpleClientset(
		&oapi.OAuthAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "token", CreationTimestamp: metav1.Time{Time: time.Now().Add(-1 * time.Hour)}},
			ExpiresIn:  600, // 10 minutes
		},
	)
	userRegistry := usertest.NewUserRegistry()
	accessTokenGetter := fakeOAuthClient.Oauth().OAuthAccessTokens()
	tokenAuthenticator := NewOAuthTokenAuthenticator(accessTokenGetter, userRegistry, identitymapper.NoopGroupMapper{})

	_, userInfo, found, err := tokenAuthenticator.AuthenticateOAuthToken("token")
	if found {
		t.Error("Found token, but it should be missing!")
	}
	if err != ErrExpired {
		t.Errorf("Unexpected error: %v", err)
	}
	if userInfo != nil {
		t.Errorf("Unexpected user: %v", userInfo)
	}
}
func TestAuthenticateTokenValidated(t *testing.T) {
	fakeOAuthClient := oauthfake.NewSimpleClientset(
		&oapi.OAuthAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "token", CreationTimestamp: metav1.Time{Time: time.Now()}},
			ExpiresIn:  600, // 10 minutes
			UserName:   "foo",
			UserUID:    string("bar"),
		},
	)
	userRegistry := usertest.NewUserRegistry()
	userRegistry.GetUsers["foo"] = &userapi.User{ObjectMeta: metav1.ObjectMeta{UID: "bar"}}
	accessTokenGetter := fakeOAuthClient.Oauth().OAuthAccessTokens()
	tokenAuthenticator := NewOAuthTokenAuthenticator(accessTokenGetter, userRegistry, identitymapper.NoopGroupMapper{})

	_, userInfo, found, err := tokenAuthenticator.AuthenticateOAuthToken("token")
	if !found {
		t.Error("Did not find a token!")
	}
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if userInfo == nil {
		t.Error("Did not get a user!")
	}
}

type oauthClientGetterFunc func(name string, options metav1.GetOptions) (*oapi.OAuthClient, error)

func (f oauthClientGetterFunc) Get(name string) (*oapi.OAuthClient, error) {
	return f(name, metav1.GetOptions{})
}

func TestAuthenticateTokenTimeout(t *testing.T) {
	var timeout int32 = 4 // 4 seconds
	fakeOAuthClient := oauthfake.NewSimpleClientset(
		&oapi.OAuthAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "token", CreationTimestamp: metav1.Time{Time: time.Now()}},
			ClientName: "testClient",
			ExpiresIn:  600, // 10 minutes
			UserName:   "foo",
			UserUID:    string("bar"),
			TimeoutsIn: timeout,
		},
		&oapi.OAuthClient{
			ObjectMeta:                metav1.ObjectMeta{Name: "testClient"},
			AccessTokenTimeoutSeconds: &timeout,
		},
	)
	userRegistry := usertest.NewUserRegistry()
	userRegistry.GetUsers["foo"] = &userapi.User{ObjectMeta: metav1.ObjectMeta{UID: "bar"}}
	accessTokenGetter := fakeOAuthClient.Oauth().OAuthAccessTokens()
	getter := oauthClientGetterFunc(fakeOAuthClient.Oauth().OAuthClients().Get)
	timeouts, _ := NewOAuthTokenTimeoutValidator(accessTokenGetter, getter, timeout)
	tokenAuthenticator := NewValidatingOAuthTokenAuthenticator(NewOAuthTokenAuthenticator(accessTokenGetter, userRegistry, identitymapper.NoopGroupMapper{}), timeouts)

	// first time should succeed
	_, userInfo, found, err := tokenAuthenticator.AuthenticateOAuthToken("token")
	if !found {
		t.Error("Did not find a token!")
	}
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if userInfo == nil {
		t.Error("Did not get a user!")
	}

	// wait for timeout
	time.Sleep(time.Second * 5)

	// this time it should fail
	_, userInfo, found, err = tokenAuthenticator.AuthenticateOAuthToken("token")
	if found {
		t.Error("Found token, but it should be missing!")
	}
	if err != ErrTimedout {
		t.Errorf("Unexpected error: %v", err)
	}
	if userInfo != nil {
		t.Errorf("Unexpected user: %v", userInfo)
	}
}

func TestTokenTimeoutNoDuplicatesBTree(t *testing.T) {
	tree := btree.New(32)
	td1 := &tokenData{
		token: &oapi.OAuthAccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name: "first",
			},
		},
		seen: time.Date(2000, 1, 1, 1, 1, 1, 1, time.UTC),
	}
	td2 := &tokenData{
		token: &oapi.OAuthAccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name: "first",
			},
		},
		seen: time.Date(2005, 1, 1, 1, 1, 1, 1, time.UTC),
	}
	td3 := &tokenData{
		token: &oapi.OAuthAccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name: "first",
			},
		},
		seen: time.Date(2010, 1, 1, 1, 1, 1, 1, time.UTC),
	}
	td4 := &tokenData{
		token: &oapi.OAuthAccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name: "second",
			},
		},
		seen: time.Date(2015, 1, 1, 1, 1, 1, 1, time.UTC),
	}

	if tree.Len() != 0 {
		t.Fatalf("Expected tree to be empty, has %d items", tree.Len())
	}

	tree.ReplaceOrInsert(td1)
	tree.ReplaceOrInsert(td2)
	tree.ReplaceOrInsert(td3)
	tree.ReplaceOrInsert(td4)

	if tree.Len() != 2 {
		t.Fatalf("Expected tree to contain only 2 items, has %d", tree.Len())
	}

	item := tree.DeleteMin()

	if tree.Len() != 1 {
		t.Fatalf("Expected tree to contain only 1 item, has %d", tree.Len())
	}

	firstToken, ok := item.(*tokenData)
	if !ok {
		t.Fatalf("Invalid token type %T", item)
	}

	if td3.token.Name != firstToken.token.Name {
		t.Fatalf("Expected token name %s, got %s", td3.token.Name, firstToken.token.Name)
	}

	if !td3.seen.Equal(firstToken.seen) {
		t.Fatalf("Expected seen %s, got %s", td3.seen, firstToken.seen)
	}

	item2 := tree.DeleteMin()

	if tree.Len() != 0 {
		t.Fatalf("Expected tree to be empty, has %d", tree.Len())
	}

	secondToken, ok := item2.(*tokenData)
	if !ok {
		t.Fatalf("Invalid token type %T", item2)
	}

	if td4.token.Name != secondToken.token.Name {
		t.Fatalf("Expected token name %s, got %s", td4.token.Name, secondToken.token.Name)
	}

	if !td4.seen.Equal(secondToken.seen) {
		t.Fatalf("Expected seen %s, got %s", td4.seen, secondToken.seen)
	}
}
