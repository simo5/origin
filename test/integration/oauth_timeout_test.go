package integration

import (
	"testing"
	"time"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	restclient "k8s.io/client-go/rest"

	"github.com/openshift/origin/pkg/cmd/util/tokencmd"
	oauthapi "github.com/openshift/origin/pkg/oauth/apis/oauth"
	oauthclient "github.com/openshift/origin/pkg/oauth/generated/internalclientset/typed/oauth/internalversion"
	userclient "github.com/openshift/origin/pkg/user/generated/internalclientset/typed/user/internalversion"
	testutil "github.com/openshift/origin/test/util"
	testserver "github.com/openshift/origin/test/util/server"
)

func TestOAuthTimeout(t *testing.T) {
	testTimeout := int32(900)
	masterOptions, err := testserver.DefaultMasterOptions()
	if err != nil {
		t.Fatal(err)
	}
	masterOptions.OAuthConfig.TokenConfig.AccessTokenTimeoutSeconds = &testTimeout
	defer testserver.CleanupMasterEtcd(t, masterOptions)

	clusterAdminKubeConfig, err := testserver.StartConfiguredMaster(masterOptions)
	if err != nil {
		t.Fatal(err)
	}

	clientConfig, err := testutil.GetClusterAdminClientConfig(clusterAdminKubeConfig)
	if err != nil {
		t.Fatal(err)
	}
	oauthClient := oauthclient.NewForConfigOrDie(clientConfig)

	// Use the server and CA info
	anonConfig := restclient.AnonymousClientConfig(clientConfig)

	{
		client, err := oauthClient.OAuthClients().Create(&oauthapi.OAuthClient{
			ObjectMeta:            metav1.ObjectMeta{Name: "defaulttimeout"},
			RespondWithChallenges: true,
			RedirectURIs:          []string{"http://localhost"},
			GrantMethod:           oauthapi.GrantHandlerAuto,
		})
		if err != nil {
			t.Fatal(err)
		}

		testTimeoutOAuthFlows(t, oauthClient.OAuthAccessTokens(), client, anonConfig, 900)
	}

	{
		client, err := oauthClient.OAuthClients().Create(&oauthapi.OAuthClient{
			ObjectMeta:                metav1.ObjectMeta{Name: "notimeout"},
			RespondWithChallenges:     true,
			RedirectURIs:              []string{"http://localhost"},
			AccessTokenTimeoutSeconds: new(int32),
			GrantMethod:               oauthapi.GrantHandlerAuto,
		})
		if err != nil {
			t.Fatal(err)
		}

		testTimeoutOAuthFlows(t, oauthClient.OAuthAccessTokens(), client, anonConfig, 0)
	}

	{
		min := int32(150)
		client, err := oauthClient.OAuthClients().Create(&oauthapi.OAuthClient{
			ObjectMeta:                metav1.ObjectMeta{Name: "shorttimeout"},
			RespondWithChallenges:     true,
			RedirectURIs:              []string{"http://localhost"},
			AccessTokenTimeoutSeconds: &min,
			GrantMethod:               oauthapi.GrantHandlerAuto,
		})
		if err != nil {
			t.Fatal(err)
		}

		token := testTimeoutOAuthFlows(t, oauthClient.OAuthAccessTokens(), client, anonConfig, int(min))

		// wait 50% of timeout time, then try token and see it still work
		time.Sleep(time.Duration(min/2) * time.Second)
		testTokenWorks(t, anonConfig, token, false)

		// Then Ensure the token times out
		time.Sleep(time.Duration(min+1) * time.Second)
		testTokenWorks(t, anonConfig, token, true)
	}
}

func testTokenWorks(t *testing.T, anonConfig *restclient.Config, token string, expectTimeout bool) {
	// Make sure we can use the token, and it represents who we expect
	userConfig := *anonConfig
	userConfig.BearerToken = token
	userClient, err := userclient.NewForConfig(&userConfig)
	if err != nil {
		t.Fatal(err)
	}

	user, err := userClient.Users().Get("~", metav1.GetOptions{})
	if err != nil {
		if expectTimeout && kerrors.IsUnauthorized(err) {
			return
		}
		t.Errorf("Unexpected error getting user ~: %v", err)
	}
	if user.Name != "username" {
		t.Errorf("Expected username as the user, got %v", user)
	}
}

func testTimeoutOAuthFlows(t *testing.T, tokens oauthclient.OAuthAccessTokenInterface, oauthClient *oauthapi.OAuthClient, anonConfig *restclient.Config, expectedTimeout int) string {
	var lastToken string

	// token flow followed by code flow
	for _, tokenFlow := range []bool{true, false} {
		tokenOpts := tokencmd.NewRequestTokenOptions(anonConfig, nil, "username", "password", tokenFlow)
		if err := tokenOpts.SetDefaultOsinConfig(); err != nil {
			t.Fatal(err)
		}
		tokenOpts.OsinConfig.ClientId = oauthClient.Name
		tokenOpts.OsinConfig.RedirectUrl = oauthClient.RedirectURIs[0]
		token, err := tokenOpts.RequestToken()
		if err != nil {
			t.Fatal(err)
		}

		// Make sure the token exists with the overridden time
		tokenObj, err := tokens.Get(token, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if tokenObj.TimeoutsIn != int32(expectedTimeout) {
			t.Errorf("Token flow=%v, expected timeout of %d, got %#v", tokenFlow, expectedTimeout, tokenObj.TimeoutsIn)
		}

		testTokenWorks(t, anonConfig, token, false)

		lastToken = token
	}

	return lastToken
}

func TestOAuthTimeoutNotEnabled(t *testing.T) {
	masterConfig, clusterAdminKubeConfig, err := testserver.StartTestMasterAPI()
	if err != nil {
		t.Fatal(err)
	}
	defer testserver.CleanupMasterEtcd(t, masterConfig)

	clientConfig, err := testutil.GetClusterAdminClientConfig(clusterAdminKubeConfig)
	if err != nil {
		t.Fatal(err)
	}
	oauthClient := oauthclient.NewForConfigOrDie(clientConfig)

	// Use the server and CA info
	anonConfig := restclient.AnonymousClientConfig(clientConfig)

	min := int32(150)
	client, err := oauthClient.OAuthClients().Create(&oauthapi.OAuthClient{
		ObjectMeta:                metav1.ObjectMeta{Name: "shorttimeoutthatisignored"},
		RespondWithChallenges:     true,
		RedirectURIs:              []string{"http://localhost"},
		AccessTokenTimeoutSeconds: &min,
		GrantMethod:               oauthapi.GrantHandlerAuto,
	})
	if err != nil {
		t.Fatal(err)
	}

	token := testTimeoutOAuthFlows(t, oauthClient.OAuthAccessTokens(), client, anonConfig, int(min))

	// ensure the token does not timeout because the feature is not active by default
	time.Sleep(time.Duration(min+30) * time.Second)
	testTokenWorks(t, anonConfig, token, false)
}
