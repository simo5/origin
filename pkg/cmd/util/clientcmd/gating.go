package clientcmd

import (
	"encoding/json"
	"fmt"

	"github.com/blang/semver"

	"github.com/openshift/origin/pkg/client"
	"github.com/openshift/origin/pkg/version"
)

// Return an error if the server is below min_server_version or above/equal
// max_server_version. To test only for min or only max version, set the
// other string to the empty value.
func Gate(ocClient *client.Client, min_server_version, max_server_version string) error {

	ocVersionBody, err := ocClient.Get().AbsPath("/version/openshift").Do().Raw()
	if err != nil {
		return err
	}
	var ocServerInfo version.Info
	err = json.Unmarshal(ocVersionBody, &ocServerInfo)
	if err != nil {
		return err
	}
	ocVersion := fmt.Sprintf("%v", ocServerInfo)
	// skip first chracter as Openshift returns a 'v' preceding the actual
	// version string which semver does not grok
	semVersion, err := semver.Parse(ocVersion[1:])
	if err != nil {
		return fmt.Errorf("Failed to parse server version, got %s", ocVersion)
	}

	if len(min_server_version) > 0 {
		if semVersion.LT(semver.MustParse(min_server_version)) {
			return fmt.Errorf("This command works only with server "+
				"versions > %s, found %s", min_server_version, ocVersion)
		}
	}

	if len(max_server_version) > 0 {
		if semVersion.GTE(semver.MustParse(max_server_version)) {
			return fmt.Errorf("This command works only with server "+
				"versions < %s, found %s", max_server_version, ocVersion)
		}
	}

	// OK this is within min/max all good!
	return nil
}
