//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/golang-jwt/jwt/v5"
)

const (
	clusterName = "csi-secret-age-cluster"
	imageName   = "csi-secret-age:e2e"
	providerName = "csi-secret-age"
	namespace   = "kube-system"
)

// getImageName returns the correct image name for the container runtime
// Podman adds "localhost/" prefix to locally built images
func getImageName() string {
	if containerRuntime == "podman" {
		return "localhost/" + imageName
	}
	return imageName
}

// Detect runtime: prefer podman if installed and docker is missing, or use env override
var containerRuntime = getContainerRuntime()

func getContainerRuntime() string {
	// Check env override
	if v := os.Getenv("CONTAINER_RUNTIME"); v != "" {
		return v
	}

	// Check if "docker" command exists and if it is actually Podman
	path, err := exec.LookPath("docker")
	if err == nil {
		cmd := exec.Command(path, "--version")
		out, err := cmd.Output()
		if err == nil && strings.Contains(strings.ToLower(string(out)), "podman") {
			return "podman"
		}
		return "docker"
	}

	// Fallback to "podman" if docker binary doesn't exist
	if _, err := exec.LookPath("podman"); err == nil {
		return "podman"
	}

	return "docker"
}

func TestE2E(t *testing.T) {
	t.Logf("Using container runtime: %s", containerRuntime)

	// 1. Setup Infrastructure
	setupCluster(t)
	defer teardownCluster(t)

	// 2. Build and Load Artifacts
	buildAndLoadImage(t)

	// 3. Deploy CSI Driver
	adminJWT := deployDriver(t)

	// 4. Install Secrets Store CSI Driver
	installSecretsStoreCSIDriver(t)

	// 5. Run Functional Tests
	t.Run("Secret Provider Smoke Test", func(t *testing.T) {
		runVolumeLifecycleTest(t)
	})

	t.Run("Secret Mounting Validation", func(t *testing.T) {
		runSecretMountingValidationTest(t, adminJWT)
	})

	t.Run("Namespace Permission Enforcement", func(t *testing.T) {
		runNamespacePermissionTest(t, adminJWT)
	})
}

func TestHelmDeployment(t *testing.T) {
	t.Logf("Using container runtime: %s", containerRuntime)

	// 1. Setup Infrastructure
	setupCluster(t)
	defer teardownCluster(t)

	// 2. Build and Load Artifacts
	buildAndLoadImage(t)

	// 3. Install Secrets Store CSI Driver
	installSecretsStoreCSIDriver(t)

	// 4. Deploy via Helm with KMS values
	deployDriverViaHelm(t)

	// 5. Verify KMS Secrets are created and DaemonSet has KMS _FILE env vars
	t.Run("KMS Secrets Created", func(t *testing.T) {
		verifyKMSSecrets(t)
	})

	t.Run("KMS File Env Vars in DaemonSet", func(t *testing.T) {
		verifyKMSEnvVars(t)
	})
}

func setupCluster(t *testing.T) {
	t.Log("Creating Kind cluster...")

	if containerRuntime == "podman" {
		os.Setenv("KIND_EXPERIMENTAL_PROVIDER", "podman")
	}

	cmd := exec.Command("kind", "get", "clusters")
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), clusterName) {
		t.Log("Cluster already exists")
		return
	}

	runCmd(t, "kind", "create", "cluster", "--name", clusterName)
}

func teardownCluster(t *testing.T) {
	if os.Getenv("SKIP_TEARDOWN") == "true" {
		t.Log("Skipping teardown...")
		return
	}
	t.Log("Deleting Kind cluster...")
	runCmd(t, "kind", "delete", "cluster", "--name", clusterName)
}

func buildAndLoadImage(t *testing.T) {
	t.Logf("Building image %s with %s...", imageName, containerRuntime)

	cmd := exec.Command(containerRuntime, "build", "-t", imageName, "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build image: %v\n%s", err, string(out))
	}

	// Save to archive (robust method for kind/podman compatibility)
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "image.tar")

	t.Log("Saving image to archive...")
	var saveCmd *exec.Cmd
	if containerRuntime == "podman" {
		saveCmd = exec.Command(containerRuntime, "save", "--format=docker-archive", "-o", archivePath, imageName)
	} else {
		saveCmd = exec.Command(containerRuntime, "save", "-o", archivePath, imageName)
	}

	if out, err := saveCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to save image archive: %v\n%s", err, string(out))
	}

	// Load archive into Kind
	t.Log("Loading archive into Kind...")
	runCmd(t, "kind", "load", "image-archive", archivePath, "--name", clusterName)

	// Verify the image is loaded
	t.Log("Verifying image is loaded in cluster...")
	nodeName := fmt.Sprintf("%s-control-plane", clusterName)
	var verifyCmd *exec.Cmd
	if containerRuntime == "podman" {
		verifyCmd = exec.Command("podman", "exec", nodeName, "crictl", "images")
	} else {
		verifyCmd = exec.Command("docker", "exec", nodeName, "crictl", "images")
	}
	out, _ := verifyCmd.CombinedOutput()
	expectedImage := getImageName()
	if !strings.Contains(string(out), expectedImage) {
		t.Logf("Warning: Image %s not found in cluster node. Loaded images:\n%s", expectedImage, string(out))
	} else {
		t.Logf("Image %s successfully loaded", expectedImage)
	}
}

func deployDriver(t *testing.T) string {
	t.Log("Deploying CSI Driver Manifests...")

	// Generate a throwaway age master key for the e2e test
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("Failed to generate age master key: %v", err)
	}
	masterKey := identity.String()

	// Generate RSA key pair for JWT validation (needed to enable PermissionManager)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	jwtPubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}))

	// Generate a JWT for the e2e admin user
	adminToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "e2e-admin",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	adminJWT, err := adminToken.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign admin JWT: %v", err)
	}

	// Create permission ConfigMap with namespace_permissions and admin_users
	permYAML := `
admin_users:
  - e2e-admin
namespace_permissions:
  e2e-test:
    - "/e2e/*"
`
	permConfigMap := fmt.Sprintf(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: csi-secret-age-perms
  namespace: %s
data:
  perm.yaml: |
%s
`, namespace, indentLines(permYAML, "    "))
	kubectlApply(t, permConfigMap)

	// Create JWT public key Secret
	jwtSecret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: jwt-public-key
  namespace: %s
stringData:
  public-key.pem: |
%s
`, namespace, indentLines(jwtPubKeyPEM, "    "))
	kubectlApply(t, jwtSecret)

	// Create the master key secret
	secretManifest := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: age-master-key
  namespace: %s
stringData:
  key.txt: "%s"
`, namespace, masterKey)
	kubectlApply(t, secretManifest)

	// Deploy RBAC + DaemonSet + Service
	manifests := fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: csi-secret-age-sa
  namespace: %s
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: csi-secret-age-role
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["csi-secret-age-backend"]
    verbs: ["get", "update"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: csi-secret-age-binding
subjects:
  - kind: ServiceAccount
    name: csi-secret-age-sa
    namespace: %s
roleRef:
  kind: ClusterRole
  name: csi-secret-age-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: csi-secret-age
  namespace: %s
spec:
  selector:
    matchLabels:
      app: csi-secret-age
  template:
    metadata:
      labels:
        app: csi-secret-age
    spec:
      serviceAccountName: csi-secret-age-sa
      hostNetwork: true
      containers:
        - name: csi-driver
          image: %s
          imagePullPolicy: Never
          ports:
            - containerPort: 8090
              name: http-admin
              protocol: TCP
          env:
            - name: MASTER_KEY_FILE
              value: /etc/csi-secret-age/secrets/master-key/key.txt
            - name: SOCKET_PATH
              value: /csi/csi-secret-age.sock
            - name: PERM_CONFIG_PATH
              value: /etc/csi-secret-age/perm.yaml
            - name: JWT_PUBLIC_KEY_FILE
              value: /etc/csi-secret-age/secrets/jwt/public-key.pem
          volumeMounts:
            - name: providers-socket-dir
              mountPath: /csi
            - name: master-key-secret
              mountPath: /etc/csi-secret-age/secrets/master-key
              readOnly: true
            - name: perms-config
              mountPath: /etc/csi-secret-age/perm.yaml
              subPath: perm.yaml
            - name: jwt-secret
              mountPath: /etc/csi-secret-age/secrets/jwt
              readOnly: true
      volumes:
        - name: providers-socket-dir
          hostPath:
            path: /var/lib/kubelet/plugins/secrets-store.csi.k8s.io/providers
            type: DirectoryOrCreate
        - name: master-key-secret
          secret:
            secretName: age-master-key
        - name: perms-config
          configMap:
            name: csi-secret-age-perms
        - name: jwt-secret
          secret:
            secretName: jwt-public-key
---
apiVersion: v1
kind: Service
metadata:
  name: csi-secret-age-admin
  namespace: %s
spec:
  selector:
    app: csi-secret-age
  ports:
    - port: 8090
      targetPort: 8090
      name: http-admin
  type: ClusterIP
`,
		namespace, namespace, namespace, getImageName(), namespace)

	kubectlApply(t, manifests)

	t.Log("Waiting for CSI Secret Age DaemonSet to be ready...")
	waitForDaemonSetPods(t, namespace, "app=csi-secret-age", 120*time.Second)

	return adminJWT
}

// deployDriverViaHelm deploys the CSI provider using the Helm chart with KMS values.
func deployDriverViaHelm(t *testing.T) {
	t.Log("Deploying CSI Driver via Helm chart with KMS values...")

	chartPath := filepath.Join("..", "deploy", "helm", "csi-secret-age")

	imgRepo := "csi-secret-age"
	imgTag := "e2e"
	if containerRuntime == "podman" {
		imgRepo = "localhost/csi-secret-age"
	}

	runCmd(t, "helm", "install", "csi-secret-age", chartPath,
		"--namespace", namespace,
		"--set", "image.repository="+imgRepo,
		"--set", "image.tag="+imgTag,
		"--set", "image.pullPolicy=Never",
		"--set", "awsKms.ciphertext=dGVzdC1hd3Mta21zLWNpcGhlcnRleHQ=",
		"--set", "gcpKms.keyName=projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
		"--set", "gcpKms.ciphertext=dGVzdC1nY3Ata21zLWNpcGhlcnRleHQ=",
		"--wait",
		"--timeout", "2m",
	)

	t.Log("Waiting for CSI Secret Age DaemonSet to be ready...")
	waitForDaemonSetPods(t, namespace, "app.kubernetes.io/name=csi-secret-age", 120*time.Second)
}

// verifyKMSSecrets checks that the AWS and GCP KMS Secrets were created by the Helm chart.
func verifyKMSSecrets(t *testing.T) {
	t.Log("Verifying KMS Secrets exist...")

	for _, secretName := range []string{"age-aws-kms-ciphertext", "age-gcp-kms-key", "age-gcp-kms-ciphertext"} {
		cmd := exec.Command("kubectl", "get", "secret", secretName, "-n", namespace, "-o", "jsonpath={.metadata.name}")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("KMS Secret %s not found: %v\nOutput: %s", secretName, err, string(out))
		}
		t.Logf("KMS Secret %s exists", strings.TrimSpace(string(out)))
	}
}

// verifyKMSEnvVars checks that the DaemonSet pod has the KMS _FILE env vars configured.
func verifyKMSEnvVars(t *testing.T) {
	t.Log("Verifying KMS _FILE env vars in DaemonSet...")

	podName := getDriverPodName(t, "app.kubernetes.io/name=csi-secret-age")

	expectedVars := map[string]string{
		"KMS_CIPHERTEXT_FILE":      "/etc/csi-secret-age/secrets/aws-kms/ciphertext",
		"GCP_KMS_KEY_NAME_FILE":   "/etc/csi-secret-age/secrets/gcp-kms/keyName",
		"GCP_KMS_CIPHERTEXT_FILE": "/etc/csi-secret-age/secrets/gcp-kms/ciphertext",
	}

	for envVar, expectedValue := range expectedVars {
		cmd := exec.Command("kubectl", "get", "pod", podName, "-n", namespace,
			"-o", fmt.Sprintf("jsonpath={.spec.containers[0].env[?(@.name=='%s')].value}", envVar))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to get env var %s from pod %s: %v\nOutput: %s", envVar, podName, err, string(out))
		}
		actual := strings.TrimSpace(string(out))
		if actual != expectedValue {
			t.Fatalf("Env var %s has wrong value: expected %s, got %s", envVar, expectedValue, actual)
		}
		t.Logf("Env var %s = %s", envVar, actual)
	}

	// Also verify the pod is running (even if locked, it should start)
	cmd := exec.Command("kubectl", "get", "pod", podName, "-n", namespace, "-o", "jsonpath={.status.phase}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to get pod phase: %v", err)
	}
	t.Logf("DaemonSet pod %s status: %s", podName, strings.TrimSpace(string(out)))
}

func runVolumeLifecycleTest(t *testing.T) {
	t.Log("Verifying CSI Secret Age driver is registered and running...")

	cmd := exec.Command("kubectl", "get", "nodes")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to get nodes: %v", err)
	}
	t.Logf("Cluster nodes:\n%s", string(out))

	t.Log("Checking CSI driver DaemonSet status...")
	cmd = exec.Command("kubectl", "get", "pods", "-n", namespace, "-l", "app=csi-secret-age")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to get CSI driver pods: %v", err)
	}
	t.Logf("CSI driver pods:\n%s", string(out))

	t.Log("Checking CSI driver logs...")
	cmd = exec.Command("kubectl", "logs", "-n", namespace, "-l", "app=csi-secret-age", "-c", "csi-driver", "--tail=10")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Logf("Warning: Could not get driver logs: %v", err)
	} else {
		t.Logf("Driver logs:\n%s", string(out))
	}

	t.Log("CSI Secret Age driver is running successfully!")
}

func runCmd(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Command failed: %s %s\nOutput: %s\nError: %v", name, strings.Join(args, " "), string(out), err)
	}
}

func kubectlApply(t *testing.T, yamlContent string) {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlContent)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to apply yaml:\n%s\nError: %v\nOutput: %s", yamlContent, err, string(out))
	}
}

func verifyData(t *testing.T, namespace, podName, mountPath, fileName, expectedContent string) {
	t.Helper()
	cmd := exec.Command("kubectl", "exec", "-n", namespace, podName, "--", "cat", fmt.Sprintf("%s/%s", mountPath, fileName))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to read file from pod %s/%s: %v\nOutput: %s", namespace, podName, err, string(out))
	}

	actualContent := strings.TrimSpace(string(out))
	if actualContent != expectedContent {
		t.Fatalf("Data persistence check failed in pod %s/%s.\nExpected: %s\nGot: %s", namespace, podName, expectedContent, actualContent)
	}
	t.Logf("Data match verified in pod %s/%s", namespace, podName)
}

func installSecretsStoreCSIDriver(t *testing.T) {
	t.Log("Installing Secrets Store CSI Driver...")

	// Add Helm repo
	runCmd(t, "helm", "repo", "add", "secrets-store-csi-driver", "https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts")
	runCmd(t, "helm", "repo", "update")

	providersDir := "/var/lib/kubelet/plugins/secrets-store.csi.k8s.io/providers"
	// Use helm upgrade --install to make the test idempotent
	runCmd(t, "helm", "upgrade", "--install", "csi-secrets-store", "secrets-store-csi-driver/secrets-store-csi-driver",
		"--namespace", "kube-system",
		"--set", "syncSecret.enabled=true",
		"--set", "linux.providersDir="+providersDir,
		"--set", "linux.nodeAffinity=null",
		"--set", "linux.additionalVolumes[0].name=providers-dir",
		"--set", "linux.additionalVolumes[0].hostPath.path="+providersDir,
		"--set", "linux.additionalVolumes[0].hostPath.type=DirectoryOrCreate",
		"--set", "linux.additionalVolumeMounts[0].name=providers-dir",
		"--set", "linux.additionalVolumeMounts[0].mountPath="+providersDir,
		"--wait",
		"--timeout", "2m",
	)

	t.Log("Secrets Store CSI Driver installed successfully")

	t.Log("Waiting for secrets-store-csi-driver pods to be ready...")
	runCmd(t, "kubectl", "wait", "--for=condition=ready", "pod", "-l", "app=secrets-store-csi-driver", "-n", "kube-system", "--timeout=60s")

	// Restart the driver to pick up the provider
	t.Log("Restarting secrets-store-csi-driver to pick up provider...")
	runCmd(t, "kubectl", "delete", "pod", "-l", "app=secrets-store-csi-driver", "-n", "kube-system")
	time.Sleep(5 * time.Second)
	runCmd(t, "kubectl", "wait", "--for=condition=ready", "pod", "-l", "app=secrets-store-csi-driver", "-n", "kube-system", "--timeout=60s")
	t.Log("Secrets-store-csi-driver restarted successfully")
}

func runSecretMountingValidationTest(t *testing.T, adminJWT string) {
	testNamespace := "e2e-test"
	testPodName := "secret-test-pod"
	mountPath := "/mnt/secrets"

	// 1. Create test namespace
	t.Log("Creating test namespace...")
	kubectlApply(t, fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %s
`, testNamespace))

	// 2. Create SecretProviderClass
	t.Log("Creating SecretProviderClass...")
	spcManifest := fmt.Sprintf(`
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: csi-secret-age-spc
  namespace: %s
spec:
  provider: %s
  parameters:
    secrets: "test-secret.txt=/e2e/test-secret"
`, testNamespace, providerName)
	kubectlApply(t, spcManifest)

	// 3. Add test secret via the admin API
	t.Log("Adding test secret via admin API...")
		addSecretViaAdminAPI(t, adminJWT, "/e2e/test-secret", "e2e-test-secret-value")

	// Wait for provider to be fully registered
	t.Log("Waiting for provider registration...")
	time.Sleep(5 * time.Second)

	// 4. Create test pod with CSI volume mount
	t.Log("Creating test pod with CSI volume mount...")
	podManifest := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - name: test-container
    image: busybox:1.36
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: secrets-volume
      mountPath: %s
      readOnly: true
  volumes:
  - name: secrets-volume
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: csi-secret-age-spc
`, testPodName, testNamespace, mountPath)
	kubectlApply(t, podManifest)

	// 5. Wait for pod to be ready
	t.Log("Waiting for test pod to be ready...")
	waitForPod(t, testNamespace, testPodName, 60*time.Second)

	// 6. Verify the secret is mounted in the pod
	t.Log("Verifying secret is mounted in the pod...")
	verifyData(t, testNamespace, testPodName, mountPath, "test-secret.txt", "e2e-test-secret-value")

	t.Log("Secret mounting validation test passed!")
}

// getDriverPodName returns the name of a running csi-secret-age pod matching the selector.
func getDriverPodName(t *testing.T, selector string) string {
	t.Helper()
	cmd := exec.Command("kubectl", "get", "pod", "-n", namespace, "-l", selector, "-o", "jsonpath={.items[0].metadata.name}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to get driver pod name: %v\nOutput: %s", err, string(out))
	}
	return strings.TrimSpace(string(out))
}

// addSecretViaAdminAPI adds a secret to the vault via its HTTP admin API
func addSecretViaAdminAPI(t *testing.T, adminJWT, secretPath, value string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Log("Port-forwarding to admin service...")

	// Start port-forward in background (service-based, works with hostNetwork pods)
	go func() {
		cmd := exec.CommandContext(ctx, "kubectl", "port-forward", "-n", namespace, "svc/csi-secret-age-admin", "8090:8090")
		if err := cmd.Run(); err != nil && ctx.Err() == nil {
			t.Logf("Port-forward error: %v", err)
		}
	}()

	// Wait for port-forward to be ready
	time.Sleep(3 * time.Second)

	// Try to add the secret via the admin API
	var lastErr error
	for i := 0; i < 5; i++ {
		data := fmt.Sprintf("path=%s&value=%s",
			secretPath, value)

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequest("POST", "http://localhost:8090/update", strings.NewReader(data))
		if err != nil {
			lastErr = err
			t.Logf("Attempt %d: Failed to create request: %v", i+1, err)
			time.Sleep(2 * time.Second)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+adminJWT)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			t.Logf("Attempt %d: Failed to add secret: %v", i+1, err)
			time.Sleep(2 * time.Second)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusSeeOther {
			t.Logf("Successfully added secret '%s' via admin API", secretPath)
			return
		}

		lastErr = fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, string(body))
		t.Logf("Attempt %d: Unexpected response: %v", i+1, lastErr)
		time.Sleep(2 * time.Second)
	}

	t.Fatalf("Failed to add secret after retries: %v", lastErr)
}

// waitForDaemonSetPods waits for at least one pod matching the selector to exist and be ready
func waitForDaemonSetPods(t *testing.T, namespace, selector string, timeout time.Duration) {
	t.Helper()
	t.Logf("Waiting for DaemonSet pods (%s) in %s to be ready...", selector, namespace)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// First, wait for pods to exist
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timeout waiting for DaemonSet pods (%s) to appear in %s", selector, namespace)
		default:
			cmd := exec.Command("kubectl", "get", "pod", "-n", namespace, "-l", selector, "-o", "name")
			out, err := cmd.CombinedOutput()
			if err == nil && len(strings.TrimSpace(string(out))) > 0 {
				break
			}
			t.Log("DaemonSet pods not yet created, waiting...")
			time.Sleep(2 * time.Second)
		}
		break
	}

	// Now wait for them to be ready
	runCmd(t, "kubectl", "wait", "--for=condition=ready", "pod", "-l", selector, "-n", namespace, "--timeout=120s")
	t.Logf("DaemonSet pods (%s) in %s are ready", selector, namespace)
}

// waitForPod waits for a pod to be in the ready state
func waitForPod(t *testing.T, namespace, podName string, timeout time.Duration) {
	t.Helper()
	t.Logf("Waiting for pod %s/%s to be ready...", namespace, podName)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timeout waiting for pod %s/%s to be ready", namespace, podName)
		default:
			cmd := exec.Command("kubectl", "get", "pod", podName, "-n", namespace, "-o", "jsonpath={.status.phase}")
			out, err := cmd.CombinedOutput()
			if err == nil && strings.TrimSpace(string(out)) == "Running" {
				// Check if all containers are ready
				readyCmd := exec.Command("kubectl", "get", "pod", podName, "-n", namespace, "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				readyOut, err := readyCmd.CombinedOutput()
				if err == nil && strings.TrimSpace(string(readyOut)) == "True" {
					t.Logf("Pod %s/%s is ready", namespace, podName)
					return
				}
			}
			time.Sleep(2 * time.Second)
		}
	}
}

// indentLines adds prefix to each non-empty line of s.
func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

// podHasFailedEvent checks if a pod has a CSI-related error event.
func podHasFailedEvent(t *testing.T, podNamespace, podName, substr string) bool {
	t.Helper()
	cmd := exec.Command("kubectl", "get", "events", "-n", podNamespace,
		"--field-selector", "involvedObject.name="+podName,
		"-o", "jsonpath={.items[*].message}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Failed to get pod events: %v", err)
		return false
	}
	return strings.Contains(string(out), substr)
}

func runNamespacePermissionTest(t *testing.T, adminJWT string) {
	allowedNS := "e2e-test"
	deniedNS := "e2e-deny"
	mountPath := "/mnt/secrets"
	secretPath := "/e2e/ns-perm-secret"
	secretValue := "namespace-permission-test-value"
	fileName := "ns-perm-secret.txt"

	// 1. Create namespaces
	t.Log("Creating test namespaces...")
	kubectlApply(t, fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %s
`, allowedNS))
	// allowedNS may already exist from previous test; that's fine

	kubectlApply(t, fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %s
`, deniedNS))

	// 2. Add a test secret via admin API (access controlled by namespace_permissions only)
	t.Log("Adding test secret via admin API...")
	addSecretViaAdminAPI(t, adminJWT, secretPath, secretValue)

	time.Sleep(3 * time.Second)

	// 3. Create a SecretProviderClass in the ALLOWED namespace
	t.Logf("Creating SecretProviderClass in %s...", allowedNS)
	spcManifest := fmt.Sprintf(`
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: csi-secret-age-ns-spc
  namespace: %s
spec:
  provider: %s
  parameters:
    secrets: "%s=%s"
`, allowedNS, providerName, fileName, secretPath)
	kubectlApply(t, spcManifest)

	// 4. Pod in ALLOWED namespace should mount successfully
	t.Logf("Creating pod in allowed namespace %s...", allowedNS)
	allowedPod := "ns-perm-allowed-pod"
	podManifest := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - name: test-container
    image: busybox:1.36
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: secrets-volume
      mountPath: %s
      readOnly: true
  volumes:
  - name: secrets-volume
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: csi-secret-age-ns-spc
`, allowedPod, allowedNS, mountPath)
	kubectlApply(t, podManifest)

	waitForPod(t, allowedNS, allowedPod, 60*time.Second)
	verifyData(t, allowedNS, allowedPod, mountPath, fileName, secretValue)
	t.Logf("Pod in allowed namespace %s successfully mounted the secret", allowedNS)

	// 5. Create a SecretProviderClass in the DENIED namespace (needs same-name SPC)
	t.Logf("Creating SecretProviderClass in %s...", deniedNS)
	spcDenied := fmt.Sprintf(`
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: csi-secret-age-ns-spc
  namespace: %s
spec:
  provider: %s
  parameters:
    secrets: "%s=%s"
`, deniedNS, providerName, fileName, secretPath)
	kubectlApply(t, spcDenied)

	// 6. Pod in DENIED namespace should be blocked
	t.Logf("Creating pod in denied namespace %s...", deniedNS)
	deniedPod := "ns-perm-denied-pod"
	deniedManifest := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - name: test-container
    image: busybox:1.36
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: secrets-volume
      mountPath: %s
      readOnly: true
  volumes:
  - name: secrets-volume
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: csi-secret-age-ns-spc
`, deniedPod, deniedNS, mountPath)
	kubectlApply(t, deniedManifest)

	// Wait up to 60s; the pod should NOT become ready
	t.Logf("Waiting for denied pod %s/%s (should fail)...", deniedNS, deniedPod)
	denied := waitForPodToFail(t, deniedNS, deniedPod, 60*time.Second)
	if !denied {
		// The pod didn't fail — check events anyway
		if podHasFailedEvent(t, deniedNS, deniedPod, "access denied") {
			t.Logf("Denied pod %s/%s has access-denied event — correct", deniedNS, deniedPod)
		} else {
			// Double-check pod state
			cmd := exec.Command("kubectl", "get", "pod", deniedPod, "-n", deniedNS, "-o", "jsonpath={.status.phase}")
			out, _ := cmd.CombinedOutput()
			if strings.TrimSpace(string(out)) == "Running" {
				t.Fatalf("Pod in denied namespace %s unexpectedly reached Running state", deniedNS)
			}
			t.Logf("Denied pod phase: %s", strings.TrimSpace(string(out)))
		}
	}

	// Verify the error event mentions access denied
	if podHasFailedEvent(t, deniedNS, deniedPod, "access denied") {
		t.Logf("Denied pod %s/%s correctly shows access denied", deniedNS, deniedPod)
	} else {
		// Acceptable outcome: pod simply never starts
		t.Logf("Denied pod %s/%s did not start (expected)", deniedNS, deniedPod)
	}
}

// waitForPodToFail waits for a pod to never become ready within the timeout.
// Returns true if the pod failed (has error events), false if it timed out without failure.
func waitForPodToFail(t *testing.T, namespace, podName string, timeout time.Duration) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		// Check if pod is Running (should NOT happen)
		cmd := exec.Command("kubectl", "get", "pod", podName, "-n", namespace, "-o", "jsonpath={.status.phase}")
		out, err := cmd.CombinedOutput()
		if err == nil && strings.TrimSpace(string(out)) == "Running" {
			return false
		}
		// Check for CSI-related error events
		if podHasFailedEvent(t, namespace, podName, "access denied") || podHasFailedEvent(t, namespace, podName, "FailedMount") {
			t.Logf("Pod %s/%s has failure event", namespace, podName)
			return true
		}
		time.Sleep(3 * time.Second)
	}
	return false
}
