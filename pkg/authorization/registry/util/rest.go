package util

import (
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/rbac/internalversion"

	authenticationapi "github.com/openshift/origin/pkg/auth/api"
	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
)

// Implements a RESTClient interface to create requests and set impersonating
// user headers
type ImpersonatingRESTClient struct {
	restClient      rest.Interface
	impersonateUser user.Info
}

func NewImpersonatingRESTClient(ctx request.Context, client rest.Interface) (*internalversion.RbacClient, error) {
	user, ok := request.UserFrom(ctx)
	if !ok {
		return nil, apierrors.NewInternalError(errors.New("missing user on request"))
	}

	ic := ImpersonatingRESTClient{
		restClient:      client,
		impersonateUser: user,
	}

	return internalversion.New(ic), nil
}

// GetRateLimiter returns rate limier for a given client, or nil if it's called on a nil client
func (c ImpersonatingRESTClient) GetRateLimiter() flowcontrol.RateLimiter {
	return c.restClient.GetRateLimiter()
}

// Here is where we do the Impersonation by setting the proper headers
func (c ImpersonatingRESTClient) Verb(verb string) *rest.Request {
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
func (c ImpersonatingRESTClient) Post() *rest.Request {
	return c.Verb("POST")
}

// Put begins a PUT request. Short for c.Verb("PUT").
func (c ImpersonatingRESTClient) Put() *rest.Request {
	return c.Verb("PUT")
}

// Patch begins a PATCH request. Short for c.Verb("Patch").
func (c ImpersonatingRESTClient) Patch(pt types.PatchType) *rest.Request {
	return c.Verb("PATCH").SetHeader("Content-Type", string(pt))
}

// Get begins a GET request. Short for c.Verb("GET").
func (c ImpersonatingRESTClient) Get() *rest.Request {
	return c.Verb("GET")
}

// Delete begins a DELETE request. Short for c.Verb("DELETE").
func (c ImpersonatingRESTClient) Delete() *rest.Request {
	return c.Verb("DELETE")
}

// APIVersion returns the APIVersion this RESTClient is expected to use.
func (c ImpersonatingRESTClient) APIVersion() schema.GroupVersion {
	return c.restClient.APIVersion()
}
