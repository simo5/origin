package role

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

func getImpersonatingClient(ctx apirequest.Context, rbacclient internalversion.RbacInterface) (internalversion.RoleInterface, error) {
	namespace, ok := apirequest.NamespaceFrom(ctx)
	if !ok {
		return nil, apierrors.NewBadRequest("namespace parameter required.")
	}
	restclient, err := util.NewImpersonatingRESTClient(ctx, rbacclient.RESTClient())
	if err != nil {
		return nil, err
	}
	return restclient.Roles(namespace), nil
}

type RoleStorage struct {
	client internalversion.RbacInterface
}

func NewREST(rbacclient internalversion.RbacInterface) *RoleStorage {
	return &RoleStorage{rbacclient}
}

func (rs *RoleStorage) New() runtime.Object {
	return &authorizationapi.Role{}
}
func (rs *RoleStorage) NewList() runtime.Object {
	return &authorizationapi.RoleList{}
}

func (rs *RoleStorage) List(ctx apirequest.Context, options *metainternal.ListOptions) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, rs.client)
	if err != nil {
		return nil, err
	}

	optv1 := metav1.ListOptions{}
	if err := metainternal.Convert_internalversion_ListOptions_To_v1_ListOptions(options, &optv1, nil); err != nil {
		return nil, err
	}

	roles, err := client.List(optv1)
	if err != nil {
		return nil, err
	}

	ret := &authorizationapi.RoleList{}
	for _, curr := range roles.Items {
		role, err := convert.RoleFromRBAC(&curr)
		if err != nil {
			return nil, err
		}
		ret.Items = append(ret.Items, *role)
	}
	return ret, err
}

func (rs *RoleStorage) Get(ctx apirequest.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, rs.client)
	if err != nil {
		return nil, err
	}

	ret, err := client.Get(name, *options)
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = apierrors.NewNotFound(authorizationapi.Resource("role"), name)
		}
		return nil, err
	}

	role, err := convert.RoleFromRBAC(ret)
	if err != nil {
		return nil, err
	}
	return role, err
}

func (rs *RoleStorage) Delete(ctx apirequest.Context, name string, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	client, err := getImpersonatingClient(ctx, rs.client)
	if err != nil {
		return nil, false, err
	}

	if err := client.Delete(name, options); err != nil {
		return nil, false, err
	}

	return &metav1.Status{Status: metav1.StatusSuccess}, true, nil
}

func (rs *RoleStorage) Create(ctx apirequest.Context, obj runtime.Object) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, rs.client)
	if err != nil {
		return nil, err
	}

	clusterObj := obj.(*authorizationapi.Role)
	convertedObj, err := convert.RoleToRBAC(clusterObj)

	ret, err := client.Create(convertedObj)
	if err != nil {
		return nil, err
	}

	role, err := convert.RoleFromRBAC(ret)
	if err != nil {
		return nil, err
	}
	return role, err
}

func (rs *RoleStorage) Update(ctx apirequest.Context, name string, objInfo rest.UpdatedObjectInfo) (runtime.Object, bool, error) {
	client, err := getImpersonatingClient(ctx, rs.client)
	if err != nil {
		return nil, false, err
	}

	old, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = apierrors.NewNotFound(authorizationapi.Resource("role"), name)
		}
		return nil, false, err
	}

	oldRole, err := convert.RoleFromRBAC(old)
	if err != nil {
		return nil, false, err
	}

	obj, err := objInfo.UpdatedObject(ctx, oldRole)
	if err != nil {
		return nil, false, err
	}

	updatedRole, err := convert.RoleToRBAC(obj.(*authorizationapi.Role))
	if err != nil {
		return nil, false, err
	}

	ret, err := client.Update(updatedRole)
	if err != nil {
		return nil, false, err
	}

	role, err := convert.RoleFromRBAC(ret)
	if err != nil {
		return nil, false, err
	}
	return role, false, err
}

// FIXME: Legacy functions, to be removed eventually
func (rs *RoleStorage) CreateRoleWithEscalation(ctx apirequest.Context, obj *authorizationapi.Role) (*authorizationapi.Role, error) {
	ret, err := rs.Create(ctx, obj)
	if err != nil {
		return nil, err
	}
	return ret.(*authorizationapi.Role), err
}

func (rs *RoleStorage) UpdateRoleWithEscalation(ctx apirequest.Context, obj *authorizationapi.Role) (*authorizationapi.Role, bool, error) {
	ret, ignored, err := rs.Update(ctx, obj.Name, rest.DefaultUpdatedObjectInfo(obj, api.Scheme))
	if err != nil {
		return nil, false, err
	}
	return ret.(*authorizationapi.Role), ignored, err
}
