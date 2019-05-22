/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certificate

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"k8s.io/client-go/tools/clientcmd"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/util/certificate"
	"k8s.io/klog"
)

type CertRotationGetter struct {
	// Path to a kubeconfig file. Required - but if the file does not exist, it can be generated using the bootstrap kubeconfig
	KubeConfig string
	// Path to a bootstrap kubeconfig file. If "", will fall back to the KubeConfig file, which must therefore exist.
	BootstrapKubeconfig string
	// Directory where certificates will be written once issued
	CertDirectory string

	// Subject information for the certificate which is to be requested
	Name pkix.Name
	// Identifier for the keypair, used in metrics and as a filename for the certificate and key
	PairNamePrefix string

	// Config overrides applied when loading either kubeconfig file
	Overrides *clientcmd.ConfigOverrides
	// Used to arbitrarily mutate the loaded config for client communication with the apiserver
	MutateClientConfig func(*rest.Config) error
	// Used to arbitrarily mutate the loaded config used for certificate rotation
	MutateCertConfig func(*rest.Config) error
}

// RestConfig obtains initial configuration using the provided kubeconfig, and rotates certificates as they expire
func (g *CertRotationGetter) RestConfig() (*rest.Config, func(), error) {
	// Rules for client rotation and the handling of kube config files:
	//
	// 1. If the client provides only a kubeconfig file, we must use that as the initial client
	//    kubeadm needs the initial data in the kubeconfig to be placed into the cert store
	// 2. If the client provides only an initial bootstrap kubeconfig file, we must create a
	//    kubeconfig file at the target location that points to the cert store, but until
	//    the file is present the client config will have no certs
	// 3. If the client provides both and the kubeconfig is valid, we must ignore the bootstrap
	//    kubeconfig.
	// 4. If the client provides both and the kubeconfig is expired or otherwise invalid, we must
	//    replace the kubeconfig with a new file that points to the cert dir
	//
	// The desired configuration for bootstrapping is to use a bootstrap kubeconfig and to have
	// the kubeconfig file be managed by this process. For backwards compatibility with kubeadm,
	// which provides a high powered kubeconfig on the master with cert/key data, we must
	// bootstrap the cert manager with the contents of the initial client config.

	klog.Infof("Client rotation is on, will bootstrap in background")
	certConfig, clientConfig, err := LoadClientConfig(g.KubeConfig, g.BootstrapKubeconfig, g.PairNamePrefix, g.CertDirectory, g.Overrides)
	if err != nil {
		return nil, nil, err
	}

	if g.MutateClientConfig != nil {
		if err := g.MutateClientConfig(clientConfig); err != nil {
			return nil, nil, err
		}
	}
	if g.MutateCertConfig != nil {
		if err := g.MutateCertConfig(clientConfig); err != nil {
			return nil, nil, err
		}
	}

	clientCertificateManager, err := buildClientCertificateManager(certConfig, clientConfig, g.PairNamePrefix, g.CertDirectory, g.Name)
	if err != nil {
		return nil, nil, err
	}

	// the rotating transport will use the cert from the cert manager instead of these files
	transportConfig := restclient.AnonymousClientConfig(clientConfig)

	// we set exitAfter to five minutes because we use this client configuration to request new certs - if we are unable
	// to request new certs, we will be unable to continue normal operation. Exiting the process allows a wrapper
	// or the bootstrapping credentials to potentially lay down new initial config.
	closeAllConns, err := UpdateTransport(wait.NeverStop, transportConfig, clientCertificateManager, 5*time.Minute)
	if err != nil {
		return nil, nil, err
	}

	klog.V(2).Info("Starting client certificate rotation.")
	clientCertificateManager.Start()

	return transportConfig, closeAllConns, nil
}

// buildClientCertificateManager creates a certificate manager that will use certConfig to request a client certificate
// if no certificate is available, or the most recent clientConfig (which is assumed to point to the cert that the manager will
// write out).
func buildClientCertificateManager(certConfig, clientConfig *restclient.Config, pairNamePrefix, certDir string, name pkix.Name) (certificate.Manager, error) {
	newClientFn := func(current *tls.Certificate) (certificatesclient.CertificateSigningRequestInterface, error) {
		// If we have a valid certificate, use that to fetch CSRs. Otherwise use the bootstrap
		// credentials. In the future it would be desirable to change the behavior of bootstrap
		// to always fall back to the external bootstrap credentials when such credentials are
		// provided by a fundamental trust system like cloud VM identity or an HSM module.
		config := certConfig
		if current != nil {
			config = clientConfig
		}
		client, err := clientset.NewForConfig(config)
		if err != nil {
			return nil, err
		}
		return client.CertificatesV1beta1().CertificateSigningRequests(), nil
	}

	return certificate.NewClientCertificateManager(
		pairNamePrefix,
		certDir,
		name,

		// this preserves backwards compatibility with kubeadm which passes
		// a high powered certificate to the kubelet as --kubeconfig and expects
		// it to be rotated out immediately
		clientConfig.CertData,
		clientConfig.KeyData,

		clientConfig.CertFile,
		clientConfig.KeyFile,
		newClientFn,
	)
}
