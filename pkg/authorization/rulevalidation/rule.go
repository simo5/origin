package rulevalidation

import (
	"k8s.io/apimachinery/pkg/labels"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbaclisters "k8s.io/kubernetes/pkg/client/listers/rbac/internalversion"
	rbacvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

type AuthorizationRoleBindingResolver interface {
	GetRoleBindings(namespace string) ([]*rbac.ClusterRoleBinding, []*rbac.RoleBinding, error)
}

type DefaultRoleBindingResolver struct {
	roleBindingLister        rbacvalidation.RoleBindingLister
	clusterRoleBindingLister rbacvalidation.ClusterRoleBindingLister
}

// TODO we should be able to delete most of this

type roleBindingLister struct {
	lister rbaclisters.RoleBindingLister
}

func (l *roleBindingLister) ListRoleBindings(namespace string) ([]*rbac.RoleBinding, error) {
	return l.lister.RoleBindings(namespace).List(labels.Everything())
}

type clusterRoleBindingLister struct {
	lister rbaclisters.ClusterRoleBindingLister
}

func (l *clusterRoleBindingLister) ListClusterRoleBindings() ([]*rbac.ClusterRoleBinding, error) {
	return l.lister.List(labels.Everything())
}

func NewDefaultRoleBindingResolver(roleBinding rbaclisters.RoleBindingLister, clusterRoleBinding rbaclisters.ClusterRoleBindingLister) *DefaultRoleBindingResolver {
	return &DefaultRoleBindingResolver{
		roleBindingLister:        &roleBindingLister{roleBinding},
		clusterRoleBindingLister: &clusterRoleBindingLister{clusterRoleBinding},
	}
}

func (r *DefaultRoleBindingResolver) GetRoleBindings(namespace string) ([]*rbac.ClusterRoleBinding, []*rbac.RoleBinding, error) {
	roleBindings := []*rbac.RoleBinding{}
	errorlist := []error{}

	clusterRoleBindings, err := r.clusterRoleBindingLister.ListClusterRoleBindings()
	if err != nil {
		errorlist = append(errorlist, err)

	}

	if len(namespace) > 0 {
		roleBindings, err = r.roleBindingLister.ListRoleBindings(namespace)
		if err != nil {
			errorlist = append(errorlist, err)
		}
	}

	return clusterRoleBindings, roleBindings, utilerrors.NewAggregate(errorlist)
}
