package ci

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	sharedPublisherSHA = "d5a29840172a53729c5999832534de65b7ba9587"
	sharedWorkflowSHA  = "d5a29840172a53729c5999832534de65b7ba9587"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	return filepath.Dir(filepath.Dir(current))
}

func readFile(t *testing.T, path ...string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(append([]string{repositoryRoot(t)}, path...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(path...), err)
	}
	return string(content)
}

func TestPublicationUsesSharedGHCRAndGARContract(t *testing.T) {
	workflow := readFile(t, ".github", "workflows", "lint-test-build-push.yml")
	for _, required := range []string{
		"libops/.github/.github/workflows/build-push.yaml@" + sharedPublisherSHA,
		"libops/.github/.github/workflows/pr-status.yaml@" + sharedWorkflowSHA,
		"\n  build-push:\n",
		"image-check:",
		"if: github.event_name == 'pull_request'",
		"if: always() && github.event_name == 'pull_request'",
		"needs-json: ${{ toJSON(needs) }}",
		"permissions: {}",
		"ubuntu-24.04-arm",
		"aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25",
		"severity: HIGH,CRITICAL",
		"goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94",
		"args: check",
		"additional-gar-registry: us-docker.pkg.dev/libops-images/public",
		"expected-main-sha:",
		"scan: true",
		"sign: true",
		"certificate-identity: https://github.com/libops/.github/.github/workflows/build-push.yaml@" + sharedPublisherSHA,
		"GCLOUD_OIDC_POOL: ${{ secrets.GCLOUD_OIDC_POOL }}",
		"GSA: ${{ secrets.GSA }}",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("publisher workflow must contain %q", required)
		}
	}
	for _, forbidden := range []string{"build-push.yaml@main", "secrets: inherit"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("publisher workflow must not contain %q", forbidden)
		}
	}
}

func TestReleasePublishesTheTaggedImage(t *testing.T) {
	release := readFile(t, ".github", "workflows", "goreleaser.yaml")
	for _, required := range []string{
		"if: github.ref_type == 'tag'",
		"uses: ./.github/workflows/lint-test-build-push.yml",
		"version: v2.17.0",
	} {
		if !strings.Contains(release, required) {
			t.Errorf("release workflow must contain %q", required)
		}
	}

	bump := readFile(t, ".github", "workflows", "github-release.yaml")
	if !strings.Contains(bump, "bump-release.yaml@"+sharedWorkflowSHA) {
		t.Fatal("release bump workflow must be pinned to the reviewed shared commit")
	}
	if !strings.Contains(bump, "workflow_file: goreleaser.yaml") {
		t.Fatal("release bump workflow must dispatch the tag workflow explicitly")
	}
	if strings.Contains(bump, "secrets: inherit") {
		t.Fatal("release bump workflow must not inherit repository secrets")
	}

	config := readFile(t, ".goreleaser.yml")
	for _, required := range []string{"version: 2", "formats:", "-X main.version={{ .Version }}"} {
		if !strings.Contains(config, required) {
			t.Errorf("GoReleaser config must contain %q", required)
		}
	}
	for _, forbidden := range []string{"before:", "format: tar.gz", "format: zip"} {
		if strings.Contains(config, forbidden) {
			t.Errorf("GoReleaser config must not contain %q", forbidden)
		}
	}
}

func TestDockerfileBuildsNativeNonRootScratchImages(t *testing.T) {
	dockerfile := readFile(t, "Dockerfile")
	for _, required := range []string{
		"FROM ghcr.io/libops/go:1.26.5@sha256:",
		"FROM scratch",
		"USER 65532:65532",
		"ENTRYPOINT [\"/bin/vault-init\"]",
		"ARG GIT_BRANCH=devel",
		"-X main.version=${GIT_BRANCH}",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Errorf("Dockerfile must contain %q", required)
		}
	}
	if strings.Contains(dockerfile, "GOARCH=") {
		t.Fatal("Dockerfile must build for the native shared-workflow architecture")
	}
}
