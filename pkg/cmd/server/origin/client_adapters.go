package origin

import rbaclisters "k8s.io/kubernetes/pkg/client/listers/rbac/internalversion"

// These adapters are temporary and will be removed when the authorization chains are refactored
// to use Listers.

type LastSyncResourceVersioner interface {
	LastSyncResourceVersion() string
}

type roleLister struct {
	rbaclisters.RoleLister
	versioner LastSyncResourceVersioner
}

func (l roleLister) LastSyncResourceVersion() string {
	return l.versioner.LastSyncResourceVersion()
}

type clusterRoleLister struct {
	rbaclisters.ClusterRoleLister
	versioner LastSyncResourceVersioner
}

func (l clusterRoleLister) LastSyncResourceVersion() string {
	return l.versioner.LastSyncResourceVersion()
}

type roleBindingLister struct {
	rbaclisters.RoleBindingLister
	versioner LastSyncResourceVersioner
}

func (l roleBindingLister) LastSyncResourceVersion() string {
	return l.versioner.LastSyncResourceVersion()
}

type clusterRoleBindingLister struct {
	rbaclisters.ClusterRoleBindingLister
	versioner LastSyncResourceVersioner
}

func (l clusterRoleBindingLister) LastSyncResourceVersion() string {
	return l.versioner.LastSyncResourceVersion()
}
