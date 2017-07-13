package bootstrappolicy

import "k8s.io/kubernetes/pkg/apis/rbac"

type PolicyData struct {
	ClusterRoles        []rbac.ClusterRole
	ClusterRoleBindings []rbac.ClusterRoleBinding
	Roles               map[string][]rbac.Role
	RoleBindings        map[string][]rbac.RoleBinding
}

func Policy() *PolicyData {
	return &PolicyData{
		ClusterRoles:        append(ClusterRoles(), ControllerRoles()...),
		ClusterRoleBindings: append(ClusterRoleBindings(), ControllerRoleBindings()...),
		Roles:               NamespaceRoles(),
		RoleBindings:        NamespaceRoleBindings(),
	}
}
