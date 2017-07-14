package rulevalidation

import (
	"k8s.io/apimachinery/pkg/labels"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbaclisters "k8s.io/kubernetes/pkg/client/listers/rbac/internalversion"
	rbacvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

type AuthorizationRbacRuleResolver interface {
	GetRoleBindings(string) ([]*rbac.ClusterRoleBinding,
		[]*rbac.RoleBinding, error)
	GetRoleReferenceRules(rbac.RoleRef, string) ([]rbac.PolicyRule, error)
	RulesFor(user.Info, string) ([]rbac.PolicyRule, error)
}

type DefaultRbacRuleResolver struct {
	roleBindingLister        rbacvalidation.RoleBindingLister
	clusterRoleBindingLister rbacvalidation.ClusterRoleBindingLister
	rbacRuleResolver         *rbacvalidation.DefaultRuleResolver
}

type roleGetter struct {
	lister rbaclisters.RoleLister
}

func (g *roleGetter) GetRole(namespace, name string) (*rbac.Role, error) {
	return g.lister.Roles(namespace).Get(name)
}

type roleBindingLister struct {
	lister rbaclisters.RoleBindingLister
}

func (l *roleBindingLister) ListRoleBindings(namespace string) ([]*rbac.RoleBinding, error) {
	return l.lister.RoleBindings(namespace).List(labels.Everything())
}

type clusterRoleGetter struct {
	lister rbaclisters.ClusterRoleLister
}

func (g *clusterRoleGetter) GetClusterRole(name string) (*rbac.ClusterRole, error) {
	return g.lister.Get(name)
}

type clusterRoleBindingLister struct {
	lister rbaclisters.ClusterRoleBindingLister
}

func (l *clusterRoleBindingLister) ListClusterRoleBindings() ([]*rbac.ClusterRoleBinding, error) {
	return l.lister.List(labels.Everything())
}

func NewDefaultRbacRuleResolver(rbacRoleLister rbaclisters.RoleLister,
	rbacRoleBindingLister rbaclisters.RoleBindingLister,
	rbacClusterRoleLister rbaclisters.ClusterRoleLister,
	rbacClusterRoleBindingLister rbaclisters.ClusterRoleBindingLister) *DefaultRbacRuleResolver {
	rl := &roleGetter{rbacRoleLister}
	rbl := &roleBindingLister{rbacRoleBindingLister}
	crl := &clusterRoleGetter{rbacClusterRoleLister}
	crbl := &clusterRoleBindingLister{rbacClusterRoleBindingLister}
	return &DefaultRbacRuleResolver{rbl, crbl,
		rbacvalidation.NewDefaultRuleResolver(rl, rbl, crl, crbl),
	}
}

func (r *DefaultRbacRuleResolver) GetRoleBindings(namespace string) ([]*rbac.ClusterRoleBinding, []*rbac.RoleBinding, error) {
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

func (r *DefaultRbacRuleResolver) GetRoleReferenceRules(roleRef rbac.RoleRef, bindingNamespace string) ([]rbac.PolicyRule, error) {
	return r.rbacRuleResolver.GetRoleReferenceRules(roleRef, bindingNamespace)
}

func (r *DefaultRbacRuleResolver) RulesFor(user user.Info, namespace string) ([]rbac.PolicyRule, error) {
	return r.rbacRuleResolver.RulesFor(user, namespace)
}
