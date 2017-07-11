package clusterrolebinding

import (
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternal "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/rbac/internalversion"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
	"github.com/openshift/origin/pkg/authorization/registry/util"
	"github.com/openshift/origin/pkg/authorization/util/convert"
)

func getImpersonatingClient(ctx apirequest.Context, rbacclient internalversion.RbacInterface) (internalversion.ClusterRoleBindingInterface, error) {
	restclient, err := util.NewImpersonatingRESTClient(ctx, rbacclient.RESTClient())
	if err != nil {
		return nil, err
	}
	return restclient.ClusterRoleBindings(), nil
}

type ClusterRoleBindingStorage struct {
	client internalversion.RbacInterface
}

func NewREST(rbacclient internalversion.RbacInterface) *ClusterRoleBindingStorage {
	return &ClusterRoleBindingStorage{rbacclient}
}

func (crbs *ClusterRoleBindingStorage) New() runtime.Object {
	return &authorizationapi.ClusterRoleBinding{}
}
func (crbs *ClusterRoleBindingStorage) NewList() runtime.Object {
	return &authorizationapi.ClusterRoleBindingList{}
}

func (crbs *ClusterRoleBindingStorage) List(ctx apirequest.Context, options *metainternal.ListOptions) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, crbs.client)
	if err != nil {
		return nil, err
	}

	optv1 := metav1.ListOptions{}
	if err := metainternal.Convert_internalversion_ListOptions_To_v1_ListOptions(options, &optv1, nil); err != nil {
		return nil, err
	}
	roles, err := client.List(optv1)
	if roles == nil {
		return nil, err
	}
	ret := &authorizationapi.ClusterRoleBindingList{}
	for _, curr := range roles.Items {
		role, err := convert.ClusterRoleBindingFromRBAC(&curr)
		if err != nil {
			return nil, err
		}
		ret.Items = append(ret.Items, *role)
	}
	return ret, err
}

func (crbs *ClusterRoleBindingStorage) Get(ctx apirequest.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, crbs.client)
	if err != nil {
		return nil, err
	}

	ret, err := client.Get(name, *options)
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = apierrors.NewNotFound(authorizationapi.Resource("clusterrolebinding"), name)
		}
		return nil, err
	}

	role, err := convert.ClusterRoleBindingFromRBAC(ret)
	if err != nil {
		return nil, err
	}
	return role, err
}

func (crbs *ClusterRoleBindingStorage) Delete(ctx apirequest.Context, name string, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	client, err := getImpersonatingClient(ctx, crbs.client)
	if err != nil {
		return nil, false, err
	}

	if err := client.Delete(name, options); err != nil {
		return nil, false, err
	}

	return &metav1.Status{Status: metav1.StatusSuccess}, true, nil
}

func (crbs *ClusterRoleBindingStorage) Create(ctx apirequest.Context, obj runtime.Object) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, crbs.client)
	if err != nil {
		return nil, err
	}

	clusterObj := obj.(*authorizationapi.ClusterRoleBinding)
	convertedObj, err := convert.ClusterRoleBindingToRBAC(clusterObj)

	ret, err := client.Create(convertedObj)
	if err != nil {
		return nil, err
	}

	role, err := convert.ClusterRoleBindingFromRBAC(ret)
	if err != nil {
		return nil, err
	}
	return role, err
}

func (crbs *ClusterRoleBindingStorage) Update(ctx apirequest.Context, name string, objInfo rest.UpdatedObjectInfo) (runtime.Object, bool, error) {
	client, err := getImpersonatingClient(ctx, crbs.client)
	if err != nil {
		return nil, false, err
	}

	old, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = apierrors.NewNotFound(authorizationapi.Resource("clusterrolebinding"), name)
		}
		return nil, false, err
	}

	oldRoleBinding, err := convert.ClusterRoleBindingFromRBAC(old)
	if err != nil {
		return nil, false, err
	}

	obj, err := objInfo.UpdatedObject(ctx, oldRoleBinding)
	if err != nil {
		return nil, false, err
	}

	updatedRoleBinding, err := convert.ClusterRoleBindingToRBAC(obj.(*authorizationapi.ClusterRoleBinding))
	if err != nil {
		return nil, false, err
	}

	ret, err := client.Update(updatedRoleBinding)
	if err != nil {
		return nil, false, err
	}

	role, err := convert.ClusterRoleBindingFromRBAC(ret)
	if err != nil {
		return nil, false, err
	}
	return role, false, err
}

// FIXME: what's escalation exactly ?
func (crbs *ClusterRoleBindingStorage) CreateClusterRoleBindingWithEscalation(ctx apirequest.Context, obj *authorizationapi.ClusterRoleBinding) (*authorizationapi.ClusterRoleBinding, error) {
	ret, err := crbs.Create(ctx, obj)
	if err != nil {
		return nil, err
	}
	return ret.(*authorizationapi.ClusterRoleBinding), err
}

func (crbs *ClusterRoleBindingStorage) UpdateClusterRoleBindingWithEscalation(ctx apirequest.Context, obj *authorizationapi.ClusterRoleBinding) (*authorizationapi.ClusterRoleBinding, bool, error) {
	ret, ignored, err := crbs.Update(ctx, obj.Name, rest.DefaultUpdatedObjectInfo(obj, api.Scheme))
	if err != nil {
		return nil, false, err
	}
	return ret.(*authorizationapi.ClusterRoleBinding), ignored, err
}
