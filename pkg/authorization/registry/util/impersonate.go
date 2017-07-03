package util

import (
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/endpoints/request"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/rest"
	rbacinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/rbac/internalversion"

	authclient "github.com/openshift/origin/pkg/auth/client"
)

func NewImpersonatingRBACFromContext(ctx apirequest.Context, restclient rest.Interface) (rbacinternalversion.RbacInterface, error) {
	user, ok := request.UserFrom(ctx)
	if !ok {
		return nil, apierrors.NewBadRequest("user missing from context")
	}
	return rbacinternalversion.New(authclient.NewImpersonatingRESTClient(user, restclient)), nil
}
