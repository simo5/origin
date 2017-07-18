package authorizer

import (
	"errors"

	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	kauthorizer "k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/kubernetes/pkg/apis/rbac"
	authorizerrbac "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"

	"github.com/openshift/origin/pkg/authorization/rulevalidation"
)

type openshiftAuthorizer struct {
	delegate              kauthorizer.Authorizer
	forbiddenMessageMaker ForbiddenMessageMaker
}

type openshiftSubjectLocator struct {
	roleToRuleMapper authorizerrbac.RoleToRuleMapper
	bindingResolver  rulevalidation.AuthorizationRoleBindingResolver
}

func NewAuthorizer(kubeauthorizer kauthorizer.Authorizer, forbiddenMessageMaker ForbiddenMessageMaker) authorizer.Authorizer {
	return &openshiftAuthorizer{delegate: kubeauthorizer, forbiddenMessageMaker: forbiddenMessageMaker}
}

// TODO replace with the RBAC one + adapter
func NewSubjectLocator(roleToRuleMapper authorizerrbac.RoleToRuleMapper, bindingResolver rulevalidation.AuthorizationRoleBindingResolver) SubjectLocator {
	return &openshiftSubjectLocator{roleToRuleMapper: roleToRuleMapper, bindingResolver: bindingResolver}
}

func (a *openshiftAuthorizer) Authorize(attributes authorizer.Attributes) (bool, string, error) {
	if attributes.GetUser() == nil {
		return false, "", errors.New("no user available on context")
	}
	allowed, _, err := a.delegate.Authorize(attributes)
	if allowed {
		return true, reason(attributes), nil
	}
	// errors are allowed to occur
	if err != nil {
		return false, "", err
	}

	denyReason, err := a.forbiddenMessageMaker.MakeMessage(attributes)
	if err != nil {
		denyReason = err.Error()
	}

	return false, denyReason, nil
}

// GetAllowedSubjects returns the subjects it knows can perform the action.
// If we got an error, then the list of subjects may not be complete, but it does not contain any incorrect names.
// This is done because policy rules are purely additive and policy determinations
// can be made on the basis of those rules that are found.
func (a *openshiftSubjectLocator) GetAllowedSubjects(attributes authorizer.Attributes) (sets.String, sets.String, error) {
	return a.getAllowedSubjectsFromNamespaceBindings(attributes)
}

func roleMatcher(r authorizerrbac.RoleToRuleMapper,
	roleRef rbac.RoleRef, subjects []rbac.Subject,
	attributes authorizer.Attributes,
	users, groups *sets.String) error {
	namespace := attributes.GetNamespace()

	rules, err := r.GetRoleReferenceRules(roleRef, namespace)
	if err != nil {
		return err
	}
	if authorizerrbac.RulesAllow(attributes, rules...) {
		for _, subject := range subjects {
			switch subject.Kind {
			case rbac.UserKind:
				users.Insert(subject.Name)
			case rbac.GroupKind:
				groups.Insert(subject.Name)
			case rbac.ServiceAccountKind:
				// default the namespace to namespace we're working in if
				// it's available. This allows rolebindings that reference
				// SAs in the local namespace to avoid having to qualify
				// them.
				ns := namespace
				if len(subject.Namespace) > 0 {
					ns = subject.Namespace
				}
				if len(ns) >= 0 {
					name := serviceaccount.MakeUsername(ns, subject.Name)
					users.Insert(name)
				}
			default:
				continue
			}
		}
	}
	return nil
}

func (a *openshiftSubjectLocator) getAllowedSubjectsFromNamespaceBindings(attributes authorizer.Attributes) (sets.String, sets.String, error) {
	var errs []error

	clusterRoleBindings, roleBindings, err := a.bindingResolver.GetRoleBindings(attributes.GetNamespace())
	if err != nil {
		errs = append(errs, err)
	}

	users := sets.String{}
	groups := sets.String{}
	for _, clusterRoleBinding := range clusterRoleBindings {
		if err := roleMatcher(a.roleToRuleMapper,
			clusterRoleBinding.RoleRef,
			clusterRoleBinding.Subjects,
			attributes, &users, &groups); err != nil {
			errs = append(errs, err)
			continue
		}
	}
	for _, roleBinding := range roleBindings {
		if err := roleMatcher(a.roleToRuleMapper,
			roleBinding.RoleRef,
			roleBinding.Subjects,
			attributes, &users, &groups); err != nil {
			errs = append(errs, err)
			continue
		}
	}

	return users, groups, kerrors.NewAggregate(errs)
}

func reason(attributes authorizer.Attributes) string {
	if len(attributes.GetNamespace()) == 0 {
		return "allowed by cluster rule"
	}
	// not 100% accurate, because the rule may have been provided by a cluster rule. we no longer have
	// this distinction upstream in practice.
	return "allowed by rule in " + attributes.GetNamespace()
}
