package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// #nosec G101: false positive triggered by variable name which includes "token"
const token = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func TestTLSCipherSuites(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	svc, err := data.clientset.CoreV1().Services(antreaNamespace).Get(context.TODO(), "antrea", metav1.GetOptions{})
	assert.NoError(t, err, "failed to get Antrea Service")
	if len(svc.Spec.Ports) == 0 {
		t.Fatal("Antrea Service has no ports")
	}
	url := fmt.Sprintf("https://%s:%d", svc.Spec.ClusterIP, svc.Spec.Ports[0].Port)

	cs := tls.TLS_RSA_WITH_AES_128_CBC_SHA
	// #nosec G402: ignore insecure options in test code
	config := &tls.Config{
		InsecureSkipVerify:       true,
		CipherSuites:             []uint16{cs},
		MaxVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: false,
	}
	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err, "failed to create HTTP request")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	assert.NoError(t, err, "failed to connect to %s", url)
	respCS := resp.TLS.CipherSuite
	defer resp.Body.Close()

	assert.Equal(t, cs, respCS, "Cipher Suite used by Server should be %s", tls.CipherSuiteName(cs))
}
