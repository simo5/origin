package bootstrappolicy

import (
	"fmt"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacbootstrappolicy "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac/bootstrappolicy"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
)

// TODO: this needs some work since we are double converting

func Policy() *rbacbootstrappolicy.PolicyData {
	return &rbacbootstrappolicy.PolicyData{
		ClusterRoles:        convertOriginClusterRolesOrDie(GetBootstrapClusterRoles()),
		ClusterRoleBindings: convertOriginClusterRoleBindingsOrDie(GetBootstrapClusterRoleBindings()),
		Roles: map[string][]rbac.Role{
			DefaultOpenShiftSharedResourcesNamespace: convertOriginRolesOrDie(GetBootstrapOpenshiftRoles(DefaultOpenShiftSharedResourcesNamespace)),
		},
		RoleBindings: map[string][]rbac.RoleBinding{
			DefaultOpenShiftSharedResourcesNamespace: convertOriginRoleBindingsOrDie(GetBootstrapOpenshiftRoleBindings(DefaultOpenShiftSharedResourcesNamespace)),
		},
	}
}

func convertOriginClusterRolesOrDie(in []authorizationapi.ClusterRole) []rbac.ClusterRole {
	out := []rbac.ClusterRole{}
	errs := []error{}

	for i := range in {
		newRole := &rbac.ClusterRole{}
		if err := kapi.Scheme.Convert(&in[i], newRole, nil); err != nil {
			errs = append(errs, fmt.Errorf("error converting %q: %v", in[i].Name, err))
			continue
		}
		out = append(out, *newRole)
	}

	if len(errs) > 0 {
		panic(errs)
	}

	return out
}

func convertOriginClusterRoleBindingsOrDie(in []authorizationapi.ClusterRoleBinding) []rbac.ClusterRoleBinding {
	out := []rbac.ClusterRoleBinding{}
	errs := []error{}

	for i := range in {
		newRoleBinding := &rbac.ClusterRoleBinding{}
		if err := kapi.Scheme.Convert(&in[i], newRoleBinding, nil); err != nil {
			errs = append(errs, fmt.Errorf("error converting %q: %v", in[i].Name, err))
			continue
		}
		out = append(out, *newRoleBinding)
	}

	if len(errs) > 0 {
		panic(errs)
	}

	return out
}

func convertOriginRolesOrDie(in []authorizationapi.Role) []rbac.Role {
	out := []rbac.Role{}
	errs := []error{}

	for i := range in {
		newRole := &rbac.Role{}
		if err := kapi.Scheme.Convert(&in[i], newRole, nil); err != nil {
			errs = append(errs, fmt.Errorf("error converting %q: %v", in[i].Name, err))
			continue
		}
		out = append(out, *newRole)
	}

	if len(errs) > 0 {
		panic(errs)
	}

	return out
}

func convertOriginRoleBindingsOrDie(in []authorizationapi.RoleBinding) []rbac.RoleBinding {
	out := []rbac.RoleBinding{}
	errs := []error{}

	for i := range in {
		newRoleBinding := &rbac.RoleBinding{}
		if err := kapi.Scheme.Convert(&in[i], newRoleBinding, nil); err != nil {
			errs = append(errs, fmt.Errorf("error converting %q: %v", in[i].Name, err))
			continue
		}
		out = append(out, *newRoleBinding)
	}

	if len(errs) > 0 {
		panic(errs)
	}

	return out
}
