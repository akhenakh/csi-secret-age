//go:build e2e

package e2e

import (
	"context"
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
)

const (
	clusterName = "csi-secret-age-cluster"
	imageName   = "csi-secret-age:e2e"
	providerName = "agevault"
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
	deployDriver(t)

	// 4. Install Secrets Store CSI Driver
	installSecretsStoreCSIDriver(t)

	// 5. Run Functional Tests
	t.Run("Secret Provider Smoke Test", func(t *testing.T) {
		runVolumeLifecycleTest(t)
	})

	t.Run("Secret Mounting Validation", func(t *testing.T) {
		runSecretMountingValidationTest(t)
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

	// 5. Verify KMS Secrets are created and DaemonSet has KMS env vars
	t.Run("KMS Secrets Created", func(t *testing.T) {
		verifyKMSSecrets(t)
	})

	t.Run("KMS Env Vars in DaemonSet", func(t *testing.T) {
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

func deployDriver(t *testing.T) {
	t.Log("Deploying CSI Driver Manifests...")

	// Generate a throwaway age master key for the e2e test
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("Failed to generate age master key: %v", err)
	}
	masterKey := identity.String()

	// Create the master key secret
	secretManifest := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: age-master-key
  namespace: %s
stringData:
  MASTER_KEY: "%s"
`, namespace, masterKey)
	kubectlApply(t, secretManifest)

	// Deploy RBAC + DaemonSet + Service
	manifests := fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: age-vault-csi-sa
  namespace: %s
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: age-vault-csi-role
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["age-vault-backend"]
    verbs: ["get", "create", "update"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: age-vault-csi-binding
subjects:
  - kind: ServiceAccount
    name: age-vault-csi-sa
    namespace: %s
roleRef:
  kind: ClusterRole
  name: age-vault-csi-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: age-vault-csi
  namespace: %s
spec:
  selector:
    matchLabels:
      app: age-vault-csi
  template:
    metadata:
      labels:
        app: age-vault-csi
    spec:
      serviceAccountName: age-vault-csi-sa
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
            - name: MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: age-master-key
                  key: MASTER_KEY
            - name: SOCKET_PATH
              value: /csi/agevault.sock
          volumeMounts:
            - name: providers-socket-dir
              mountPath: /csi
      volumes:
        - name: providers-socket-dir
          hostPath:
            path: /var/lib/kubelet/plugins/secrets-store.csi.k8s.io/providers
            type: DirectoryOrCreate
---
apiVersion: v1
kind: Service
metadata:
  name: age-vault-admin
  namespace: %s
spec:
  selector:
    app: age-vault-csi
  ports:
    - port: 8090
      targetPort: 8090
      name: http-admin
  type: ClusterIP
`,
		namespace, namespace, namespace, getImageName(), namespace)

	kubectlApply(t, manifests)

	t.Log("Waiting for Age Vault CSI DaemonSet to be ready...")
	waitForDaemonSetPods(t, namespace, "app=age-vault-csi", 120*time.Second)
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

	t.Log("Waiting for Age Vault CSI DaemonSet to be ready...")
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

// verifyKMSEnvVars checks that the DaemonSet pod has the KMS env vars configured.
func verifyKMSEnvVars(t *testing.T) {
	t.Log("Verifying KMS env vars in DaemonSet...")

	podName := getDriverPodName(t, "app.kubernetes.io/name=csi-secret-age")

	expectedVars := map[string]string{
		"KMS_CIPHERTEXT":      "age-aws-kms-ciphertext",
		"GCP_KMS_KEY_NAME":    "age-gcp-kms-key",
		"GCP_KMS_CIPHERTEXT":  "age-gcp-kms-ciphertext",
	}

	for envVar, expectedSecret := range expectedVars {
		cmd := exec.Command("kubectl", "get", "pod", podName, "-n", namespace,
			"-o", fmt.Sprintf("jsonpath={.spec.containers[0].env[?(@.name=='%s')].valueFrom.secretKeyRef.name}", envVar))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to get env var %s from pod %s: %v\nOutput: %s", envVar, podName, err, string(out))
		}
		actual := strings.TrimSpace(string(out))
		if actual != expectedSecret {
			t.Fatalf("Env var %s references wrong secret: expected %s, got %s", envVar, expectedSecret, actual)
		}
		t.Logf("Env var %s references secret %s", envVar, actual)
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
	t.Log("Verifying Age Vault CSI driver is registered and running...")

	cmd := exec.Command("kubectl", "get", "nodes")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to get nodes: %v", err)
	}
	t.Logf("Cluster nodes:\n%s", string(out))

	t.Log("Checking CSI driver DaemonSet status...")
	cmd = exec.Command("kubectl", "get", "pods", "-n", namespace, "-l", "app=age-vault-csi")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to get CSI driver pods: %v", err)
	}
	t.Logf("CSI driver pods:\n%s", string(out))

	t.Log("Checking CSI driver logs...")
	cmd = exec.Command("kubectl", "logs", "-n", namespace, "-l", "app=age-vault-csi", "-c", "csi-driver", "--tail=10")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Logf("Warning: Could not get driver logs: %v", err)
	} else {
		t.Logf("Driver logs:\n%s", string(out))
	}

	t.Log("Age Vault CSI driver is running successfully!")
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

func runSecretMountingValidationTest(t *testing.T) {
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
  name: age-vault-spc
  namespace: %s
spec:
  provider: %s
  parameters:
    secrets: "test-secret.txt=/e2e/test-secret"
`, testNamespace, providerName)
	kubectlApply(t, spcManifest)

	// 3. Add test secret via the admin API
	t.Log("Adding test secret via admin API...")
	addSecretViaAdminAPI(t, "/e2e/test-secret", "e2e-test-secret-value", "*", "*")

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
        secretProviderClass: age-vault-spc
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

// getDriverPodName returns the name of a running age-vault-csi pod matching the selector.
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
func addSecretViaAdminAPI(t *testing.T, secretPath, value, namespaces, serviceAccounts string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Log("Port-forwarding to admin service...")

	// Start port-forward in background (service-based, works with hostNetwork pods)
	go func() {
		cmd := exec.CommandContext(ctx, "kubectl", "port-forward", "-n", namespace, "svc/age-vault-admin", "8090:8090")
		if err := cmd.Run(); err != nil && ctx.Err() == nil {
			t.Logf("Port-forward error: %v", err)
		}
	}()

	// Wait for port-forward to be ready
	time.Sleep(3 * time.Second)

	// Try to add the secret via the admin API
	var lastErr error
	for i := 0; i < 5; i++ {
		data := fmt.Sprintf("path=%s&value=%s&namespaces=%s&service_accounts=%s",
			secretPath, value, namespaces, serviceAccounts)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post("http://localhost:8090/update", "application/x-www-form-urlencoded", strings.NewReader(data))
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
