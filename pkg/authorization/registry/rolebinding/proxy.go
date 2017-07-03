package rolebinding

import (
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternal "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/rbac/internalversion"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
	"github.com/openshift/origin/pkg/authorization/registry/util"
)

// FIXME: deep copies
func rbacToRoleBinding(in *rbac.RoleBinding) (authorizationapi.RoleBinding, error) {
	var out authorizationapi.RoleBinding
	err := authorizationapi.Convert_rbac_RoleBinding_To_authorization_RoleBinding(in, &out, nil)
	return out, err
}

func rbacFromRoleBinding(in *authorizationapi.RoleBinding) (rbac.RoleBinding, error) {
	var out rbac.RoleBinding
	err := authorizationapi.Convert_authorization_RoleBinding_To_rbac_RoleBinding(in, &out, nil)
	return out, err
}

func getImpersonatingClient(ctx apirequest.Context, rbacclient internalversion.RbacInterface) (internalversion.RoleBindingInterface, error) {
	namespace, ok := apirequest.NamespaceFrom(ctx)
	if !ok {
		return nil, apierrors.NewBadRequest("namespace parameter required.")
	}

	restclient, err := util.NewImpersonatingRESTClient(ctx, rbacclient.RESTClient())
	if err != nil {
		return nil, err
	}

	return restclient.RoleBindings(namespace), nil
}

type RoleBindingStorage struct {
	client internalversion.RbacInterface
}

func NewREST(rbacclient internalversion.RbacInterface) *RoleBindingStorage {
	return &RoleBindingStorage{rbacclient}
}

func (rbs *RoleBindingStorage) New() runtime.Object {
	return &authorizationapi.RoleBinding{}
}
func (rbs *RoleBindingStorage) NewList() runtime.Object {
	return &authorizationapi.RoleBindingList{}
}

func (rbs *RoleBindingStorage) List(ctx apirequest.Context, options *metainternal.ListOptions) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, rbs.client)
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

	ret := &authorizationapi.RoleBindingList{}
	for _, curr := range roles.Items {
		role, err := rbacToRoleBinding(&curr)
		if err != nil {
			return nil, err
		}
		ret.Items = append(ret.Items, role)
	}
	return ret, err
}

func (rbs *RoleBindingStorage) Get(ctx apirequest.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, rbs.client)
	if err != nil {
		return nil, err
	}

	ret, err := client.Get(name, *options)
	if err != nil {
		return nil, err
	}

	role, err := rbacToRoleBinding(ret)
	if err != nil {
		return nil, err
	}
	return &role, err
}

func (rbs *RoleBindingStorage) Delete(ctx apirequest.Context, name string, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	client, err := getImpersonatingClient(ctx, rbs.client)
	if err != nil {
		return nil, false, err
	}

	if err := client.Delete(name, options); err != nil {
		return nil, false, err
	}

	return &metav1.Status{Status: metav1.StatusSuccess}, true, nil
}

func (rbs *RoleBindingStorage) Create(ctx apirequest.Context, obj runtime.Object) (runtime.Object, error) {
	client, err := getImpersonatingClient(ctx, rbs.client)
	if err != nil {
		return nil, err
	}

	clusterObj := obj.(*authorizationapi.RoleBinding)
	convertedObj, err := rbacFromRoleBinding(clusterObj)

	ret, err := client.Create(&convertedObj)
	if err != nil {
		return nil, err
	}

	role, err := rbacToRoleBinding(ret)
	if err != nil {
		return nil, err
	}
	return &role, err
}

func (rbs *RoleBindingStorage) Update(ctx apirequest.Context, name string, objInfo rest.UpdatedObjectInfo) (runtime.Object, bool, error) {
	client, err := getImpersonatingClient(ctx, rbs.client)
	if err != nil {
		return nil, false, err
	}

	old, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = apierrors.NewNotFound(rbac.Resource("clusterrolebinding"), name)
		}
		return nil, false, err
	}

	oldRoleBinding, err := rbacToRoleBinding(old)
	if err != nil {
		return nil, false, err
	}

	obj, err := objInfo.UpdatedObject(ctx, &oldRoleBinding)
	if err != nil {
		return nil, false, err
	}

	updatedRoleBinding, err := rbacFromRoleBinding(obj.(*authorizationapi.RoleBinding))
	if err != nil {
		return nil, false, err
	}

	ret, err := client.Update(&updatedRoleBinding)
	if err != nil {
		return nil, false, err
	}

	role, err := rbacToRoleBinding(ret)
	if err != nil {
		return nil, false, err
	}
	return &role, false, err
}

// FIXME: Legacy functions, to be removed eventually
func (rbs *RoleBindingStorage) CreateRoleBindingWithEscalation(ctx apirequest.Context, obj *authorizationapi.RoleBinding) (*authorizationapi.RoleBinding, error) {
	ret, err := rbs.Create(ctx, obj)
	if err != nil {
		return nil, err
	}
	return ret.(*authorizationapi.RoleBinding), err
}

func (rbs *RoleBindingStorage) UpdateRoleBindingWithEscalation(ctx apirequest.Context, obj *authorizationapi.RoleBinding) (*authorizationapi.RoleBinding, bool, error) {
	ret, ignored, err := rbs.Update(ctx, obj.Name, rest.DefaultUpdatedObjectInfo(obj, api.Scheme))
	if err != nil {
		return nil, false, err
	}
	return ret.(*authorizationapi.RoleBinding), ignored, err
}
