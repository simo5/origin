package integration

import (
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
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
		t.Fatalf("unexpected error: %v", err)
	}
	masterOptions.OAuthConfig.TokenConfig.AccessTokenTimeoutSeconds = &testTimeout
	defer testserver.CleanupMasterEtcd(t, masterOptions)

	clusterAdminKubeConfig, err := testserver.StartConfiguredMaster(masterOptions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	clientConfig, err := testutil.GetClusterAdminClientConfig(clusterAdminKubeConfig)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	oauthClient := oauthclient.NewForConfigOrDie(clientConfig)

	// Use the server and CA info
	anonConfig := restclient.AnonymousClientConfig(clientConfig)

	{
		client, err := oauthClient.OAuthClients().Create(&oauthapi.OAuthClient{
			ObjectMeta:            metav1.ObjectMeta{Name: "notimeout"},
			RespondWithChallenges: true,
			RedirectURIs:          []string{"http://localhost"},
			GrantMethod:           oauthapi.GrantHandlerAuto,
		})
		if err != nil {
			t.Fatal(err)
		}

		testTimeoutOAuthFlows(t, clientConfig, client, anonConfig, 0)
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

		token := testTimeoutOAuthFlows(t, clientConfig, client, anonConfig, int(min))

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
		t.Fatalf("Unexpected error: %v", err)
	}

	user, err := userClient.Users().Get("~", metav1.GetOptions{})
	if err != nil {
		if expectTimeout && kerrors.IsUnauthorized(err) {
			return
		}
		t.Fatalf("Unexpected error: %v", err)
	}
	if user.Name != "username" {
		t.Fatalf("Expected username as the user, got %v", user)
	}
}

func testTimeoutOAuthFlows(t *testing.T, clusterAdminClientConfig *restclient.Config, oauthClient *oauthapi.OAuthClient, anonConfig *restclient.Config, expectedTimeout int) string {
	oauthClientset := oauthclient.NewForConfigOrDie(clusterAdminClientConfig)

	// token flow
	{
		tokenOpts := tokencmd.NewRequestTokenOptions(anonConfig, nil, "username", "password", true)
		if err := tokenOpts.SetDefaultOsinConfig(); err != nil {
			t.Fatal(err)
		}
		tokenOpts.OsinConfig.ClientId = oauthClient.Name
		tokenOpts.OsinConfig.RedirectUrl = oauthClient.RedirectURIs[0]
		if len(tokenOpts.OsinConfig.CodeChallenge) != 0 || len(tokenOpts.OsinConfig.CodeChallengeMethod) != 0 || len(tokenOpts.OsinConfig.CodeVerifier) != 0 {
			t.Fatalf("incorrectly set PKCE for OAuth client %q during token flow", oauthClient.Name)
		}
		token, err := tokenOpts.RequestToken()
		if err != nil {
			t.Fatal(err)
		}

		// Make sure the token exists with the overridden time
		if expectedTimeout > 0 {
			tokenObj, err := oauthClientset.OAuthAccessTokens().Get(token, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if tokenObj.TimeoutsIn != int32(expectedTimeout) {
				t.Fatalf("Expected timeout of %d, got %#v", expectedTimeout, tokenObj.TimeoutsIn)
			}
		}

		testTokenWorks(t, anonConfig, token, false)
	}

	// code flow
	{
		rt, err := restclient.TransportFor(anonConfig)
		if err != nil {
			t.Fatal(err)
		}

		conf := &oauth2.Config{
			ClientID:     oauthClient.Name,
			ClientSecret: oauthClient.Secret,
			RedirectURL:  oauthClient.RedirectURIs[0],
			Endpoint: oauth2.Endpoint{
				AuthURL:  anonConfig.Host + "/oauth/authorize",
				TokenURL: anonConfig.Host + "/oauth/token",
			},
		}

		// get code
		req, err := http.NewRequest("GET", conf.AuthCodeURL(""), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("username", "password")
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("unexpected status %v", resp.StatusCode)
		}
		location, err := resp.Location()
		if err != nil {
			t.Fatal(err)
		}
		code := location.Query().Get("code")
		if len(code) == 0 {
			t.Fatalf("Unexpected response: %v", location)
		}

		// Use the custom HTTP client when requesting a token.
		httpClient := &http.Client{Transport: rt}
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
		oauthToken, err := conf.Exchange(ctx, code)
		if err != nil {
			t.Fatal(err)
		}
		token := oauthToken.AccessToken

		// Make sure the token exists with the overridden time
		if expectedTimeout > 0 {
			tokenObj, err := oauthClientset.OAuthAccessTokens().Get(token, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if tokenObj.TimeoutsIn != int32(expectedTimeout) {
				t.Fatalf("Expected expiration of %d, got %#v", expectedTimeout, tokenObj.TimeoutsIn)
			}
		}

		testTokenWorks(t, anonConfig, token, false)

		return token
	}
}
