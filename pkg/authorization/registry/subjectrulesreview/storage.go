package subjectrulesreview

import (
	"fmt"
	"sort"

	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	kutilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/user"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	rbaclisters "k8s.io/kubernetes/pkg/client/listers/rbac/internalversion"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
	"github.com/openshift/origin/pkg/authorization/authorizer/scope"
	"github.com/openshift/origin/pkg/authorization/rulevalidation"
)

type REST struct {
	ruleResolver      rbacregistryvalidation.AuthorizationRuleResolver
	clusterRoleGetter rbaclisters.ClusterRoleLister
}

func NewREST(ruleResolver rbacregistryvalidation.AuthorizationRuleResolver, clusterRoleGetter rbaclisters.ClusterRoleLister) *REST {
	return &REST{ruleResolver: ruleResolver, clusterRoleGetter: clusterRoleGetter}
}

func (r *REST) New() runtime.Object {
	return &authorizationapi.SubjectRulesReview{}
}

// Create registers a given new ResourceAccessReview instance to r.registry.
func (r *REST) Create(ctx apirequest.Context, obj runtime.Object, _ bool) (runtime.Object, error) {
	rulesReview, ok := obj.(*authorizationapi.SubjectRulesReview)
	if !ok {
		return nil, kapierrors.NewBadRequest(fmt.Sprintf("not a SubjectRulesReview: %#v", obj))
	}
	namespace := apirequest.NamespaceValue(ctx)
	if len(namespace) == 0 {
		return nil, kapierrors.NewBadRequest(fmt.Sprintf("namespace is required on this type: %v", namespace))
	}

	userToCheck := &user.DefaultInfo{
		Name:   rulesReview.Spec.User,
		Groups: rulesReview.Spec.Groups,
		Extra:  map[string][]string{},
	}
	if len(rulesReview.Spec.Scopes) > 0 {
		userToCheck.Extra[authorizationapi.ScopesKey] = rulesReview.Spec.Scopes
	}

	rules, errors := GetEffectivePolicyRules(apirequest.WithUser(ctx, userToCheck), r.ruleResolver, r.clusterRoleGetter)

	ret := &authorizationapi.SubjectRulesReview{
		Status: authorizationapi.SubjectRulesReviewStatus{
			Rules: rules,
		},
	}

	if len(errors) != 0 {
		ret.Status.EvaluationError = kutilerrors.NewAggregate(errors).Error()
	}

	return ret, nil
}

func GetEffectivePolicyRules(ctx apirequest.Context, ruleResolver rbacregistryvalidation.AuthorizationRuleResolver, clusterRoleGetter rbaclisters.ClusterRoleLister) ([]authorizationapi.PolicyRule, []error) {
	namespace := apirequest.NamespaceValue(ctx)
	if len(namespace) == 0 {
		return nil, []error{kapierrors.NewBadRequest(fmt.Sprintf("namespace is required on this type: %v", namespace))}
	}
	user, exists := apirequest.UserFrom(ctx)
	if !exists {
		return nil, []error{kapierrors.NewBadRequest(fmt.Sprintf("user missing from context"))}
	}

	var errors []error
	var rules []authorizationapi.PolicyRule
	namespaceRules, err := ruleResolver.RulesFor(user, namespace)
	if err != nil {
		errors = append(errors, err)
	}
	for _, rule := range authorizationapi.Convert_rbac_PolicyRules_To_authorization_PolicyRules(namespaceRules) { // TODO fix this nonsense
		rules = append(rules, rulevalidation.BreakdownRule(rule)...)
	}

	if scopes := user.GetExtra()[authorizationapi.ScopesKey]; len(scopes) > 0 {
		rules, err = filterRulesByScopes(rules, scopes, namespace, clusterRoleGetter)
		if err != nil {
			return nil, []error{kapierrors.NewInternalError(err)}
		}
	}

	if compactedRules, err := rulevalidation.CompactRules(rules); err == nil {
		rules = compactedRules
	}
	sort.Sort(authorizationapi.SortableRuleSlice(rules))

	return rules, errors
}

func filterRulesByScopes(rules []authorizationapi.PolicyRule, scopes []string, namespace string, clusterRoleGetter rbaclisters.ClusterRoleLister) ([]authorizationapi.PolicyRule, error) {
	rbacScopeRules, err := scope.ScopesToRules(scopes, namespace, clusterRoleGetter)
	if err != nil {
		return nil, err
	}
	scopeRules := authorizationapi.Convert_rbac_PolicyRules_To_authorization_PolicyRules(rbacScopeRules)

	filteredRules := []authorizationapi.PolicyRule{}
	for _, rule := range rules {
		if allowed, _ := rulevalidation.Covers(scopeRules, []authorizationapi.PolicyRule{rule}); allowed {
			filteredRules = append(filteredRules, rule)
		}
	}

	return filteredRules, nil
}
