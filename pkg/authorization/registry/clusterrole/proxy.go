package clusterrole

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

func getImpersonatingClient(ctx apirequest.Context, rbacclient internalversion.RbacInterface) (internalversion.ClusterRoleInterface, error) {
	restclient, err := util.NewImpersonatingRESTClient(ctx, rbacclient.RESTClient())
	if err != nil {
		return nil, err
	}
	return restclient.ClusterRoles(), nil
}

type ClusterRoleStorage struct {
	client internalversion.RbacInterface
}

func NewREST(rbacclient internalversion.RbacInterface) *ClusterRoleStorage {
	return &ClusterRoleStorage{rbacclient}
}

func (crs *ClusterRoleStorage) New() runtime.Object {
	return &authorizationapi.ClusterRole{}
}
func (crs *ClusterRoleStorage) NewList() runtime.Object {
	return &authorizationapi.ClusterRoleList{}
}

func (crs *ClusterRoleStorage) List(ctx apirequest.Context, options *metainternal.ListOptions) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, crs.client)
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

	ret := &authorizationapi.ClusterRoleList{}
	for _, curr := range roles.Items {
		role, err := convert.ClusterRoleFromRBAC(&curr)
		if err != nil {
			return nil, err
		}
		ret.Items = append(ret.Items, *role)
	}
	return ret, err
}

func (crs *ClusterRoleStorage) Get(ctx apirequest.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, crs.client)
	if err != nil {
		return nil, err
	}

	ret, err := client.Get(name, *options)
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = apierrors.NewNotFound(authorizationapi.Resource("clusterrole"), name)
		}
		return nil, err
	}

	role, err := convert.ClusterRoleFromRBAC(ret)
	if err != nil {
		return nil, err
	}
	return role, err
}

func (crs *ClusterRoleStorage) Delete(ctx apirequest.Context, name string, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	client, err := getImpersonatingClient(ctx, crs.client)
	if err != nil {
		return nil, false, err
	}

	if err := client.Delete(name, options); err != nil {
		return nil, false, err
	}

	return &metav1.Status{Status: metav1.StatusSuccess}, true, nil
}

func (crs *ClusterRoleStorage) Create(ctx apirequest.Context, obj runtime.Object, _ bool) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, crs.client)
	if err != nil {
		return nil, err
	}

	clusterObj := obj.(*authorizationapi.ClusterRole)
	convertedObj, err := convert.ClusterRoleToRBAC(clusterObj)

	ret, err := client.Create(convertedObj)
	if err != nil {
		return nil, err
	}

	role, err := convert.ClusterRoleFromRBAC(ret)
	if err != nil {
		return nil, err
	}
	return role, err
}

func (crs *ClusterRoleStorage) Update(ctx apirequest.Context, name string, objInfo rest.UpdatedObjectInfo) (runtime.Object, bool, error) {
	client, err := getImpersonatingClient(ctx, crs.client)
	if err != nil {
		return nil, false, err
	}

	old, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = apierrors.NewNotFound(authorizationapi.Resource("clusterrole"), name)
		}
		return nil, false, err
	}

	oldRole, err := convert.ClusterRoleFromRBAC(old)
	if err != nil {
		return nil, false, err
	}

	obj, err := objInfo.UpdatedObject(ctx, oldRole)
	if err != nil {
		return nil, false, err
	}

	updatedRole, err := convert.ClusterRoleToRBAC(obj.(*authorizationapi.ClusterRole))
	if err != nil {
		return nil, false, err
	}

	ret, err := client.Update(updatedRole)
	if err != nil {
		return nil, false, err
	}

	role, err := convert.ClusterRoleFromRBAC(ret)
	if err != nil {
		return nil, false, err
	}
	return role, false, err
}

func (crs *ClusterRoleStorage) CreateClusterRoleWithEscalation(ctx apirequest.Context, obj *authorizationapi.ClusterRole) (*authorizationapi.ClusterRole, error) {
	ret, err := crs.Create(ctx, obj, false)
	if err != nil {
		return nil, err
	}
	return ret.(*authorizationapi.ClusterRole), err
}

func (crs *ClusterRoleStorage) UpdateClusterRoleWithEscalation(ctx apirequest.Context, obj *authorizationapi.ClusterRole) (*authorizationapi.ClusterRole, bool, error) {
	ret, ignored, err := crs.Update(ctx, obj.Name, rest.DefaultUpdatedObjectInfo(obj, api.Scheme))
	if err != nil {
		return nil, false, err
	}
	return ret.(*authorizationapi.ClusterRole), ignored, err
}
