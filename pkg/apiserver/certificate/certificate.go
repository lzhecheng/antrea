// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certificate

import (
	"fmt"
	"net"
	"os"
	"path"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/kubernetes"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/klog"
	"k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/vmware-tanzu/antrea/pkg/util/env"
	"github.com/vmware-tanzu/antrea/pkg/util/ip"
)

var (
	// certDir is the directory that the TLS Secret should be mounted to. Declaring it as a variable for testing.
	certDir = "/var/run/antrea/antrea-controller-tls"

	// selfSignedCertDir is the dir Antrea self signed certificates are created in.
	selfSignedCertDir = "/var/run/antrea/antrea-controller-self-signed"
	// certReadyTimeout is the timeout we will wait for the TLS Secret being ready. Declaring it as a variable for testing.
	certReadyTimeout = 2 * time.Minute

	// maxRotateDuration is the max duration for rotating self-signed certificate generated by Antrea.
	// In most cases we will rotate the certificate when we reach half the expiration time of the certificate (see nextRotationDuration).
	// maxRotateDuration ensures that if a self-signed certificate has a really long expiration (N years), we still attempt to rotate it
	// within a reasonable time, in this case one year. maxRotateDuration is also used to force certificate rotation in unit tests.
	maxRotateDuration = time.Hour * (24 * 365)
)

const (
	// The names of the files that should contain the CA certificate and the TLS key pair.
	CACertFile  = "ca.crt"
	TLSCertFile = "tls.crt"
	TLSKeyFile  = "tls.key"

	defaultAntreaNamespace = "kube-system"
)

// GetAntreaServerNames returns the DNS names that the TLS certificate will be signed with.
func GetAntreaServerNames() []string {
	namespace := env.GetPodNamespace()
	if namespace == "" {
		klog.Warningf("Failed to get Pod Namespace from environment. Using \"%s\" as the Antrea Service Namespace", defaultAntreaNamespace)
		namespace = defaultAntreaNamespace
	}

	antreaServerName := "antrea." + namespace + ".svc"
	// TODO: Although antrea-agent and kube-aggregator only verify the server name "antrea.<Namespace>.svc",
	// We should add the whole FQDN "antrea.<Namespace>.svc.<Cluster Domain>" as an alternate DNS name when
	// other clients need to access it directly with that name.
	return []string{antreaServerName}
}

func ApplyServerCert(selfSignedCert bool, client kubernetes.Interface, aggregatorClient clientset.Interface,
	secureServing *options.SecureServingOptionsWithLoopback) (*CACertController, error) {
	var err error
	var caContentProvider dynamiccertificates.CAContentProvider
	if selfSignedCert {
		caContentProvider, err = generateSelfSignedCertificate(secureServing)
		if err != nil {
			return nil, fmt.Errorf("error creating self-signed CA certificate: %v", err)
		}
	} else {
		caCertPath := path.Join(certDir, CACertFile)
		tlsCertPath := path.Join(certDir, TLSCertFile)
		tlsKeyPath := path.Join(certDir, TLSKeyFile)
		// The secret may be created after the Pod is created, for example, when cert-manager is used the secret
		// is created asynchronously. It waits for a while before it's considered to be failed.
		if err = wait.PollImmediate(2*time.Second, certReadyTimeout, func() (bool, error) {
			for _, path := range []string{caCertPath, tlsCertPath, tlsKeyPath} {
				f, err := os.Open(path)
				if err != nil {
					klog.Warningf("Couldn't read %s when applying server certificate, retrying", path)
					return false, nil
				}
				f.Close()
			}
			return true, nil
		}); err != nil {
			return nil, fmt.Errorf("error reading TLS certificate and/or key. Please make sure the TLS CA (%s), cert (%s), and key (%s) files are present in \"%s\", when selfSignedCert is set to false", CACertFile, TLSCertFile, TLSKeyFile, certDir)
		}
		// Since 1.17.0 (https://github.com/kubernetes/kubernetes/commit/3f5fbfbfac281f40c11de2f57d58cc332affc37b),
		// apiserver reloads certificate cert and key file from disk every minute, allowing serving tls config to be updated.
		secureServing.ServerCert.CertKey.CertFile = tlsCertPath
		secureServing.ServerCert.CertKey.KeyFile = tlsKeyPath

		caContentProvider, err = dynamiccertificates.NewDynamicCAContentFromFile("user-provided CA cert", caCertPath)
		if err != nil {
			return nil, fmt.Errorf("error reading user-provided CA certificate: %v", err)
		}
	}

	caCertController := newCACertController(caContentProvider, client, aggregatorClient)

	if selfSignedCert {
		go rotateSelfSignedCertificates(caCertController, secureServing, maxRotateDuration)
	}

	return caCertController, nil
}

// generateSelfSignedCertificate generates a new self signed certificate.
func generateSelfSignedCertificate(secureServing *options.SecureServingOptionsWithLoopback) (dynamiccertificates.CAContentProvider, error) {
	var err error
	var caContentProvider dynamiccertificates.CAContentProvider

	// Set the PairName and CertDirectory to generate the certificate files.
	secureServing.ServerCert.CertDirectory = selfSignedCertDir
	secureServing.ServerCert.PairName = "antrea-controller"

	if err := secureServing.MaybeDefaultWithSelfSignedCerts("antrea", GetAntreaServerNames(), []net.IP{ip.IPv4loopback, net.IPv6loopback}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	caContentProvider, err = dynamiccertificates.NewDynamicCAContentFromFile("self-signed cert", secureServing.ServerCert.CertKey.CertFile)
	if err != nil {
		return nil, fmt.Errorf("error reading self-signed CA certificate: %v", err)
	}

	return caContentProvider, nil
}

// Used to determine which is sooner, the provided maxRotateDuration or the expiration date
// of the cert. Used to allow for unit testing with a far shorter rotation period.
// Also can be used to pass a user provided rotation window.
func nextRotationDuration(secureServing *options.SecureServingOptionsWithLoopback,
	maxRotateDuration time.Duration) (time.Duration, error) {

	x509Cert, err := certutil.CertsFromFile(secureServing.ServerCert.CertKey.CertFile)
	if err != nil {
		return time.Duration(0), fmt.Errorf("error parsing generated certificate: %v", err)
	}

	// Attempt to rotate the certificate at the half-way point of expiration.
	// Unless the halfway point is longer than maxRotateDuration
	duration := x509Cert[0].NotAfter.Sub(time.Now()) / 2

	waitDuration := duration
	if maxRotateDuration < waitDuration {
		waitDuration = maxRotateDuration
	}

	return waitDuration, nil
}

// rotateSelfSignedCertificates calculates the rotation duration for the current certificate.
// Then once the duration is complete, generates a new self-signed certificate and repeats the process.
func rotateSelfSignedCertificates(c *CACertController, secureServing *options.SecureServingOptionsWithLoopback,
	maxRotateDuration time.Duration) {
	for {
		rotationDuration, err := nextRotationDuration(secureServing, maxRotateDuration)
		if err != nil {
			klog.Errorf("error reading expiration date of cert: %v", err)
			return
		}

		klog.Infof("Certificate will be rotated at %v", time.Now().Add(rotationDuration))

		time.Sleep(rotationDuration)

		klog.Infof("Rotating self signed certificate")

		err = generateNewServingCertificate(secureServing)
		if err != nil {
			klog.Errorf("error generating new cert: %v", err)
			return
		}
		c.UpdateCertificate()
	}
}

func generateNewServingCertificate(secureServing *options.SecureServingOptionsWithLoopback) error {
	cert, key, err := certutil.GenerateSelfSignedCertKeyWithFixtures("antrea", []net.IP{ip.IPv4loopback, net.IPv6loopback}, GetAntreaServerNames(), secureServing.ServerCert.FixtureDirectory)
	if err != nil {
		return fmt.Errorf("unable to generate self signed cert: %v", err)
	}

	if err := certutil.WriteCert(secureServing.ServerCert.CertKey.CertFile, cert); err != nil {
		return err
	}
	if err := keyutil.WriteKey(secureServing.ServerCert.CertKey.KeyFile, key); err != nil {
		return err
	}
	klog.Infof("Generated self-signed cert (%s, %s)", secureServing.ServerCert.CertKey.CertFile, secureServing.ServerCert.CertKey.KeyFile)

	return nil
}
