package dns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang/glog"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/route53"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

const (
	cloudDNSServiceAccountKey = "service-account.json"
)

type solver interface {
	Present(domain, token, key string) error
	CleanUp(domain, token, key string) error
	Timeout() (timeout, interval time.Duration)
}

type Solver struct {
	issuer            v1alpha1.GenericIssuer
	client            kubernetes.Interface
	secretLister      corev1listers.SecretLister
	resourceNamespace string
}

func (s *Solver) Present(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	slv, err := s.solverFor(crt, domain)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Presenting DNS01 challenge for domain %q", domain)
	return slv.Present(domain, token, key)
}

func (s *Solver) Wait(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	slv, err := s.solverFor(crt, domain)
	if err != nil {
		return err
	}

	type boolErr struct {
		bool
		error
	}

	fqdn, value, ttl := util.DNS01Record(domain, key)

	glog.V(4).Infof("Checking DNS propagation for %q using name servers: %v", domain, util.RecursiveNameservers)

	timeout, interval := slv.Timeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		select {
		case r := <-func() <-chan boolErr {
			out := make(chan boolErr, 1)
			go func() {
				defer close(out)
				ok, err := util.PreCheckDNS(fqdn, value)
				out <- boolErr{ok, err}
			}()
			return out
		}():
			if r.bool {
				// TODO: move this to somewhere else
				// TODO: make this wait for whatever the record *was*, not is now
				glog.V(4).Infof("Waiting DNS record TTL (%ds) to allow propagation for propagation of DNS record for domain %q", ttl, fqdn)
				time.Sleep(time.Second * time.Duration(ttl))
				glog.V(4).Infof("ACME DNS01 validation record propagated for %q", fqdn)
				return nil
			}
			glog.V(4).Infof("DNS record for %q not yet propagated", domain)
			time.Sleep(interval)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Solver) CleanUp(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	slv, err := s.solverFor(crt, domain)
	if err != nil {
		return err
	}
	return slv.CleanUp(domain, token, key)
}

func (s *Solver) solverFor(crt *v1alpha1.Certificate, domain string) (solver, error) {
	var cfg *v1alpha1.ACMECertificateDNS01Config
	if cfg = crt.Spec.ACME.ConfigForDomain(domain).DNS01; cfg == nil ||
		cfg.Provider == "" ||
		s.issuer.GetSpec().ACME == nil ||
		s.issuer.GetSpec().ACME.DNS01 == nil {
		return nil, fmt.Errorf("no dns01 config found for domain %q", domain)
	}

	providerConfig, err := s.issuer.GetSpec().ACME.DNS01.Provider(cfg.Provider)
	if err != nil {
		return nil, fmt.Errorf("invalid provider config specified for domain %q: %s", domain, err)
	}

	var impl solver
	switch {
	case providerConfig.CloudDNS != nil:
		saBytes, err := s.resolveSecretKeyRef(providerConfig.CloudDNS.ServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("error getting clouddns service account: %s", err)
		}

		impl, err = clouddns.NewDNSProviderServiceAccountBytes(providerConfig.CloudDNS.Project, saBytes)
		if err != nil {
			return nil, fmt.Errorf("error instantiating google clouddns challenge solver: %s", err)
		}
	case providerConfig.Cloudflare != nil:
		apiKey, err := s.resolveSecretKeyRef(providerConfig.Cloudflare.APIKey)
		if err != nil {
			return nil, fmt.Errorf("error getting cloudflare service account: %s", err)
		}

		email := providerConfig.Cloudflare.Email

		impl, err = cloudflare.NewDNSProviderCredentials(email, string(apiKey))
		if err != nil {
			return nil, fmt.Errorf("error instantiating cloudflare challenge solver: %s", err)
		}
	case providerConfig.Route53 != nil:
		secretAccessKey, err := s.resolveSecretKeyRef(providerConfig.Route53.SecretAccessKeyRef)
		if err != nil {
			return nil, fmt.Errorf("error getting route53 secret access key: %s", err)
		}

		accessKey := providerConfig.Route53.AccessKeyID
		if accessKey == "" {
			accessKeyFromSecret, err := s.resolveSecretKeyRef(providerConfig.Route53.AccessKeyIDRef)
			if err == errEmptyRef {
				return nil, fmt.Errorf("no route53 access key provided: 'accessKeyID' or 'accessKeyIDRef' must be set")
			}
			if err != nil {
				return nil, fmt.Errorf("error getting route53 access key from secret: %s", err)
			}
			accessKey = string(accessKeyFromSecret)
		}

		impl, err = route53.NewDNSProviderAccessKey(
			accessKey,
			string(secretAccessKey),
			providerConfig.Route53.HostedZoneID,
			providerConfig.Route53.Region,
		)
		if err != nil {
			return nil, fmt.Errorf("error instantiating route53 challenge solver: %s", err)
		}
	default:
		return nil, fmt.Errorf("no dns provider config specified for domain %q", domain)
	}

	return impl, nil
}

var errEmptyRef = errors.New("secret key reference was empty")

func (s *Solver) resolveSecretKeyRef(ref v1alpha1.SecretKeySelector) ([]byte, error) {
	if ref.Name == "" {
		return nil, errEmptyRef
	}
	key, err := s.secretLister.Secrets(s.resourceNamespace).Get(ref.Name)
	if err != nil {
		return nil, fmt.Errorf("error getting secret %q: %s", ref.Name, err)
	}
	secretBytes, ok := key.Data[ref.Key]
	if !ok {
		return nil, fmt.Errorf("error getting secret key ref %q: not found in secret %q", ref.Name, ref.Key)
	}
	return secretBytes, nil
}

func NewSolver(issuer v1alpha1.GenericIssuer, client kubernetes.Interface, secretLister corev1listers.SecretLister, resourceNamespace string) *Solver {
	return &Solver{issuer, client, secretLister, resourceNamespace}
}
