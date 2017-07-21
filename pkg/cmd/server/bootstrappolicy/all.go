package bootstrappolicy

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/errors"
	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacbootstrappolicy "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac/bootstrappolicy"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
)

// TODO: this needs some work since we are double converting

func Policy() *rbacbootstrappolicy.PolicyData {
	return &rbacbootstrappolicy.PolicyData{
		ClusterRoles:        GetBootstrapClusterRoles(),
		ClusterRoleBindings: GetBootstrapClusterRoleBindings(),
		Roles: map[string][]rbac.Role{
			DefaultOpenShiftSharedResourcesNamespace: GetBootstrapOpenshiftRoles(DefaultOpenShiftSharedResourcesNamespace),
		},
		RoleBindings: map[string][]rbac.RoleBinding{
			DefaultOpenShiftSharedResourcesNamespace: GetBootstrapOpenshiftRoleBindings(DefaultOpenShiftSharedResourcesNamespace),
		},
	}
}

func InvertOriginClusterRolesOrDie(in []rbac.ClusterRole) []authorizationapi.ClusterRole {
	out := []authorizationapi.ClusterRole{}
	errs := []error{}

	for i := range in {
		newRole := &authorizationapi.ClusterRole{}
		if err := kapi.Scheme.Convert(&in[i], newRole, nil); err != nil {
			errs = append(errs, fmt.Errorf("error converting %q: %v", in[i].Name, err))
			continue
		}
		out = append(out, *newRole)
	}

	if len(errs) > 0 {
		panic(errors.NewAggregate(errs).Error())
	}

	return out
}

func InvertOriginClusterRoleBindingsOrDie(in []rbac.ClusterRoleBinding) []authorizationapi.ClusterRoleBinding {
	out := []authorizationapi.ClusterRoleBinding{}
	errs := []error{}

	for i := range in {
		newRoleBinding := &authorizationapi.ClusterRoleBinding{}
		if err := kapi.Scheme.Convert(&in[i], newRoleBinding, nil); err != nil {
			errs = append(errs, fmt.Errorf("error converting %q: %v", in[i].Name, err))
			continue
		}
		out = append(out, *newRoleBinding)
	}

	if len(errs) > 0 {
		panic(errors.NewAggregate(errs).Error())
	}

	return out
}
