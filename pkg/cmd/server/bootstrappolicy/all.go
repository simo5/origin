package bootstrappolicy

import (
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacbootstrappolicy "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac/bootstrappolicy"
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
