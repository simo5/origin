package client

import (
	"errors"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
	kclientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"

	authenticationapi "github.com/openshift/origin/pkg/auth/api"
	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
	"github.com/openshift/origin/pkg/client"
	utilnet "k8s.io/apimachinery/pkg/util/net"
)

type impersonatingRoundTripper struct {
	user     user.Info
	delegate http.RoundTripper
}

// NewImpersonatingRoundTripper will add headers to impersonate a user, including user, groups, and scopes
func NewImpersonatingRoundTripper(user user.Info, delegate http.RoundTripper) http.RoundTripper {
	return &impersonatingRoundTripper{user, delegate}
}

func (rt *impersonatingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = utilnet.CloneRequest(req)
	req.Header.Del(authenticationapi.ImpersonateUserHeader)
	req.Header.Del(authenticationapi.ImpersonateGroupHeader)
	req.Header.Del(authenticationapi.ImpersonateUserScopeHeader)

	req.Header.Set(authenticationapi.ImpersonateUserHeader, rt.user.GetName())
	for _, group := range rt.user.GetGroups() {
		req.Header.Add(authenticationapi.ImpersonateGroupHeader, group)
	}
	for _, scope := range rt.user.GetExtra()[authorizationapi.ScopesKey] {
		req.Header.Add(authenticationapi.ImpersonateUserScopeHeader, scope)
	}
	return rt.delegate.RoundTrip(req)
}

// NewImpersonatingConfig wraps the config's transport to impersonate a user, including user, groups, and scopes
func NewImpersonatingConfig(user user.Info, config restclient.Config) restclient.Config {
	oldWrapTransport := config.WrapTransport
	config.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		return NewImpersonatingRoundTripper(user, oldWrapTransport(rt))
	}
	return config
}

// NewImpersonatingOpenShiftClient returns an OpenShift client that will impersonate a user, including user, groups, and scopes
func NewImpersonatingOpenShiftClient(user user.Info, config restclient.Config) (client.Interface, error) {
	impersonatingConfig := NewImpersonatingConfig(user, config)
	return client.New(&impersonatingConfig)
}

// NewImpersonatingKubernetesClientset returns a Kubernetes clientset that will impersonate a user, including user, groups, and scopes
func NewImpersonatingKubernetesClientset(user user.Info, config restclient.Config) (kclientset.Interface, error) {
	impersonatingConfig := NewImpersonatingConfig(user, config)
	return kclientset.NewForConfig(&impersonatingConfig)
}

// Implements a RESTClient interface to create requests and set impersonating
// user headers
type ImpersonatingRESTClient struct {
	restClient      restclient.Interface
	impersonateUser user.Info
}

func NewImpersonatingRESTClient(ctx request.Context, client restclient.Interface) (*ImpersonatingRESTClient, error) {
	user, ok := request.UserFrom(ctx)
	if !ok {
		return nil, apierrors.NewInternalError(errors.New("missing user on request"))
	}

	return &ImpersonatingRESTClient{
		restClient:      client,
		impersonateUser: user,
	}, nil
}

// GetRateLimiter returns rate limier for a given client, or nil if it's called on a nil client
func (c ImpersonatingRESTClient) GetRateLimiter() flowcontrol.RateLimiter {
	return c.restClient.GetRateLimiter()
}

// Here is where we do the Impersonation by setting the proper headers
func (c ImpersonatingRESTClient) Verb(verb string) *restclient.Request {
	req := c.restClient.Verb(verb)
	// SetHeader creates the headers struct if nil
	req.SetHeader(authenticationapi.ImpersonateUserHeader,
		c.impersonateUser.GetName())
	req.SetHeaderValues(authenticationapi.ImpersonateGroupHeader,
		c.impersonateUser.GetGroups())
	req.SetHeaderValues(authenticationapi.ImpersonateUserScopeHeader,
		c.impersonateUser.GetExtra()[authorizationapi.ScopesKey])
	return req
}

// Post begins a POST request. Short for c.Verb("POST").
func (c ImpersonatingRESTClient) Post() *restclient.Request {
	return c.Verb("POST")
}

// Put begins a PUT request. Short for c.Verb("PUT").
func (c ImpersonatingRESTClient) Put() *restclient.Request {
	return c.Verb("PUT")
}

// Patch begins a PATCH request. Short for c.Verb("Patch").
func (c ImpersonatingRESTClient) Patch(pt types.PatchType) *restclient.Request {
	return c.Verb("PATCH").SetHeader("Content-Type", string(pt))
}

// Get begins a GET request. Short for c.Verb("GET").
func (c ImpersonatingRESTClient) Get() *restclient.Request {
	return c.Verb("GET")
}

// Delete begins a DELETE request. Short for c.Verb("DELETE").
func (c ImpersonatingRESTClient) Delete() *restclient.Request {
	return c.Verb("DELETE")
}

// APIVersion returns the APIVersion this RESTClient is expected to use.
func (c ImpersonatingRESTClient) APIVersion() schema.GroupVersion {
	return c.restClient.APIVersion()
}
