package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type scrapeConfig []struct {
	HonorTimestamps bool   `yaml:"honor_timestamps"`
	JobName         string `yaml:"job_name"`
	MetricsPath     string `yaml:"metrics_path"`
	Params          struct {
		Module []string `yaml:"module"`
	} `yaml:"params"`
	RelabelConfigs []struct {
		SourceLabels []string `yaml:"source_labels,omitempty"`
		TargetLabel  string   `yaml:"target_label,omitempty"`
		Replacement  string   `yaml:"replacement,omitempty"`
	} `yaml:"relabel_configs"`
	Scheme         string `yaml:"scheme"`
	ScrapeInterval string `yaml:"scrape_interval"`
	ScrapeTimeout  string `yaml:"scrape_timeout"`
	StaticConfigs  []struct {
		Targets []string `yaml:"targets"`
		Labels  struct {
			Module string `yaml:"module"`
		} `yaml:"labels"`
	} `yaml:"static_configs"`
}

type environmentVariables struct {
	PublicHostedZoneID   string
	PrivateHostedZoneID  string
	PrometheusNamespace  string
	PrometheusSecretName string
	MattermostAlertsHook string
	ExcludedTargets      []string
	AdditionalTargets    []string
	DevMode              string
	BindServers          []string
}

func main() {
	envVars, err := validateAndGetEnvVars()
	if err != nil {
		log.WithError(err).Error("Environment variable validation failed")
		err = sendMattermostErrorNotification(err, "Environment variable validation failed")
		if err != nil {
			log.WithError(err).Error("Failed to send Mattermost error notification")
		}
		os.Exit(1)
	}

	err = blackboxTargetDiscovery(envVars)
	if err != nil {
		log.WithError(err).Error("Failed to run Blackbox target discovery")
		err = sendMattermostErrorNotification(err, "The Blackbox target discovery failed")
		if err != nil {
			log.WithError(err).Error("Failed to send Mattermost error notification")
		}
		os.Exit(1)
	}
}

// validateEnvironmentVariables is used to validate the environment variables needed by Blackbox target discovery.
func validateAndGetEnvVars() (*environmentVariables, error) {
	envVars := &environmentVariables{}
	publiHostedZoneID := os.Getenv("PUBLIC_HOSTED_ZONE_ID")
	if len(publiHostedZoneID) == 0 {
		return nil, errors.Errorf("PUBLIC_HOSTED_ZONE_ID environment variable is not set")
	}
	envVars.PublicHostedZoneID = publiHostedZoneID

	privateHostedZoneID := os.Getenv("PRIVATE_HOSTED_ZONE_ID")
	if len(privateHostedZoneID) == 0 {
		return nil, errors.Errorf("PRIVATE_HOSTED_ZONE_ID environment variable is not set")
	}
	envVars.PrivateHostedZoneID = privateHostedZoneID

	prometheusNamespace := os.Getenv("PROMETHEUS_NAMESPACE")
	if len(prometheusNamespace) == 0 {
		return nil, errors.Errorf("PROMETHEUS_NAMESPACE environment variable is not set")
	}
	envVars.PrometheusNamespace = prometheusNamespace

	excludedTargets := os.Getenv("EXCLUDED_TARGETS")
	if len(excludedTargets) > 0 {
		envVars.ExcludedTargets = strings.Split(excludedTargets, ",")
	}

	additionalTargets := os.Getenv("ADDITIONAL_TARGETS")
	if len(additionalTargets) > 0 {
		envVars.AdditionalTargets = strings.Split(additionalTargets, ",")
	}

	prometheusSecretName := os.Getenv("PROMETHEUS_SECRET_NAME")
	if len(prometheusSecretName) == 0 {
		return nil, errors.Errorf("PROMETHEUS_SECRET_NAME environment variable is not set.")
	}
	envVars.PrometheusSecretName = prometheusSecretName

	mattermostAlertsHook := os.Getenv("MATTERMOST_ALERTS_HOOK")
	if len(mattermostAlertsHook) == 0 {
		return nil, errors.Errorf("MATTERMOST_ALERTS_HOOK environment variable is not set.")
	}
	envVars.MattermostAlertsHook = mattermostAlertsHook

	developerMode := os.Getenv("DEVELOPER_MODE")
	if len(developerMode) == 0 {
		envVars.DevMode = "false"
	} else {
		envVars.DevMode = developerMode
	}

	bindServers := os.Getenv("BIND_SERVERS")
	if len(bindServers) > 0 {
		envVars.BindServers = strings.Split(bindServers, ",")
	}

	return envVars, nil
}

// blackboxTargetDiscovery is used to keep Prometheus up to date with Blackbox targets.
func blackboxTargetDiscovery(envVars *environmentVariables) error {
	log.Infof("Getting Route53 records for public hostedzone %s", envVars.PublicHostedZoneID)
	publicRecords, err := listAllRecordSets(envVars.PublicHostedZoneID)
	if err != nil {
		return errors.Wrap(err, "Unable to get the existing public Route53 records")
	}

	log.Infof("Getting Route53 records for private hostedzone %s", envVars.PrivateHostedZoneID)
	privateRecords, err := listAllRecordSets(envVars.PrivateHostedZoneID)
	if err != nil {
		return errors.Wrap(err, "Unable to get the existing private Route53 records")
	}

	log.Info("Getting Blackbox targets")
	blackBoxTargets := getBlackBoxTargets(publicRecords, privateRecords, envVars.AdditionalTargets, envVars.ExcludedTargets)
	if len(blackBoxTargets) < 1 {
		log.Info("No targets to register, canceling run")
		return nil
	}

	log.Info("Getting k8s client")
	clientset, err := getClientSet(envVars)
	if err != nil {
		return errors.Wrap(err, "Unable to create k8s clientset")
	}

	log.Info("Reading scrape config yaml file")
	scrapeConfigFile, err := ioutil.ReadFile("scrapeconfig.yml")
	if err != nil {
		return errors.Wrap(err, "Error reading scrape config file")
	}

	log.Info("Parsing scrape config file")
	var config scrapeConfig
	err = yaml.Unmarshal(scrapeConfigFile, &config)
	if err != nil {
		return errors.Wrap(err, "Error parsing scrape config file")
	}

	log.Info("Adding new targets in config")
	config[0].StaticConfigs[0].Targets = blackBoxTargets

	//Adding Bind server targets
	for i, bindServer := range envVars.BindServers {
		config[i+1].StaticConfigs[0].Targets = []string{bindServer}
	}

	data, err := yaml.Marshal(&config)
	if err != nil {
		return errors.Wrap(err, "Error running marshal for config file")
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: envVars.PrometheusSecretName,
		},
		Data: map[string][]byte{"scrape_config_secret.yaml": data},
	}

	log.Info("Creating/updating Blackbox targets Prometheus secret")
	_, err = createOrUpdateSecret(envVars.PrometheusNamespace, envVars.PrometheusSecretName, secret, clientset)
	if err != nil {
		return errors.Wrap(err, "failed to create the Blackbox targets Prometheus secret")
	}
	log.Info("Successfully updated Blackbox targets")

	return nil
}

// getClientSet gets the k8s clientset
func getClientSet(envVars *environmentVariables) (*kubernetes.Clientset, error) {
	if envVars.DevMode == "true" {
		kubeconfig := filepath.Join(
			os.Getenv("HOME"), ".kube", "config",
		)

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, err
		}

		return clientset, nil
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

// listAllRecordSets is used to get the existing Route53 Records
func listAllRecordSets(hostedZoneID string) ([]*route53.ResourceRecordSet, error) {
	var err error

	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}

	// Create Route53 service client
	svc := route53.New(sess)

	req := route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(hostedZoneID),
		StartRecordName: aws.String("c"),
		StartRecordType: aws.String("CNAME"),
	}

	var rrsets []*route53.ResourceRecordSet

	for {
		var resp *route53.ListResourceRecordSetsOutput
		resp, err = svc.ListResourceRecordSets(&req)
		if err != nil {
			return nil, err
		}
		rrsets = append(rrsets, resp.ResourceRecordSets...)
		if *resp.IsTruncated {
			req.StartRecordName = resp.NextRecordName
			req.StartRecordType = resp.NextRecordType
			req.StartRecordIdentifier = resp.NextRecordIdentifier
		} else {
			break
		}
	}

	return rrsets, nil
}

// getBlackBoxTargets is used to get all Blackbox target that need to be registered.
func getBlackBoxTargets(publicRecords, privateRecords []*route53.ResourceRecordSet, additionalTargets, excludedTargets []string) []string {
	blackBoxTargets := []string{}
	for _, record := range publicRecords {
		if !isExcludedTarget(excludedTargets, *record.Name) && !strings.HasPrefix(*record.Name, "_") {
			blackBoxTargets = append(blackBoxTargets, fmt.Sprintf("%s/api/v4/system/ping", *record.Name))
		}

	}

	for _, record := range privateRecords {
		if !isExcludedTarget(excludedTargets, *record.Name) && !strings.HasPrefix(*record.Name, "_") {
			if strings.Contains(*record.Name, "-grpc.") {
				blackBoxTargets = append(blackBoxTargets, fmt.Sprintf("%s:9090", *record.Name))
			}
		}
	}

	for _, target := range additionalTargets {
		log.Infof("Adding additional target %s", target)
		blackBoxTargets = append(blackBoxTargets, target)
	}
	log.Info("Returning Blackbox targets")

	return blackBoxTargets
}

// isExcludedTarget checks if a Route53 record is in the excluded targets
func isExcludedTarget(excludedTargets []string, record string) bool {
	if len(excludedTargets) > 0 {
		for _, target := range excludedTargets {
			if target == record {
				return true
			}
		}
	}

	return false
}

// createOrUpdateSecret creates or update a secret
func createOrUpdateSecret(prometheusNamespace, secretName string, secret *corev1.Secret, clientset *kubernetes.Clientset) (metav1.Object, error) {
	ctx := context.TODO()
	_, err := clientset.CoreV1().Secrets(prometheusNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return nil, err
	}

	if err != nil && k8sErrors.IsNotFound(err) {
		return clientset.CoreV1().Secrets(prometheusNamespace).Create(ctx, secret, metav1.CreateOptions{})
	}

	return clientset.CoreV1().Secrets(prometheusNamespace).Update(ctx, secret, metav1.UpdateOptions{})
}
