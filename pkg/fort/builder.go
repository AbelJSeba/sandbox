package fort

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

// Builder creates container images from synthesized configurations
type Builder struct {
	docker *client.Client
	config BuilderConfig
}

// BuilderConfig holds builder configuration
type BuilderConfig struct {
	BuildTimeout time.Duration
	NoCache      bool
	Labels       map[string]string
}

// DefaultBuilderConfig returns sensible defaults
func DefaultBuilderConfig() BuilderConfig {
	return BuilderConfig{
		BuildTimeout: 5 * time.Minute,
		NoCache:      false,
		Labels: map[string]string{
			"fort.managed": "true",
		},
	}
}

// NewBuilder creates a new Builder
func NewBuilder(dockerClient *client.Client, config BuilderConfig) *Builder {
	return &Builder{
		docker: dockerClient,
		config: config,
	}
}

// NewBuilderFromEnv creates a Builder using environment Docker config
func NewBuilderFromEnv(config BuilderConfig) (*Builder, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}
	return NewBuilder(dockerClient, config), nil
}

// BuildResult contains the result of a build operation
type BuildResult struct {
	ImageID   string
	ImageTag  string
	BuildLogs string
	Duration  time.Duration
}

// Build creates a container image from synthesis result
func (b *Builder) Build(ctx context.Context, req *Request, synthesis *SynthesisResult) (*BuildResult, error) {
	startTime := time.Now()

	// Create build context timeout
	buildCtx, cancel := context.WithTimeout(ctx, b.config.BuildTimeout)
	defer cancel()

	// Generate unique image tag
	imageTag := fmt.Sprintf("fort-exec-%s:%d", req.ID, time.Now().Unix())

	// Create tar archive with build context
	buildContext, err := b.createBuildContext(req, synthesis)
	if err != nil {
		return nil, fmt.Errorf("failed to create build context: %w", err)
	}

	// Prepare build labels
	labels := make(map[string]string)
	for k, v := range b.config.Labels {
		labels[k] = v
	}
	labels["fort.request_id"] = req.ID
	labels["fort.language"] = synthesis.BaseImage
	labels["fort.created_at"] = time.Now().UTC().Format(time.RFC3339)

	// Build options
	buildOptions := types.ImageBuildOptions{
		Tags:        []string{imageTag},
		Dockerfile:  "Dockerfile",
		Remove:      true,
		ForceRemove: true,
		NoCache:     b.config.NoCache,
		Labels:      labels,
		BuildArgs:   make(map[string]*string),
	}

	// Add build args from synthesis
	for _, arg := range synthesis.BuildArgs {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) == 2 {
			buildOptions.BuildArgs[parts[0]] = &parts[1]
		}
	}

	// Execute build
	response, err := b.docker.ImageBuild(buildCtx, buildContext, buildOptions)
	if err != nil {
		return nil, fmt.Errorf("docker build failed: %w", err)
	}
	defer response.Body.Close()

	// Read build output
	var buildLogs bytes.Buffer
	_, err = io.Copy(&buildLogs, response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read build output: %w", err)
	}

	// Check for build errors in output
	logsStr := buildLogs.String()
	if strings.Contains(logsStr, "error") && strings.Contains(logsStr, "failed") {
		return nil, fmt.Errorf("build failed: %s", logsStr)
	}

	// Get image ID
	imageInspect, _, err := b.docker.ImageInspectWithRaw(ctx, imageTag)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect built image: %w", err)
	}

	return &BuildResult{
		ImageID:   imageInspect.ID,
		ImageTag:  imageTag,
		BuildLogs: logsStr,
		Duration:  time.Since(startTime),
	}, nil
}

// createBuildContext creates a tar archive containing the build context
func (b *Builder) createBuildContext(req *Request, synthesis *SynthesisResult) (io.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add Dockerfile
	if err := addToTar(tw, "Dockerfile", []byte(synthesis.Dockerfile)); err != nil {
		return nil, err
	}

	// Add entry script if present
	if synthesis.EntryScript != "" {
		if err := addToTar(tw, "run.sh", []byte(synthesis.EntryScript)); err != nil {
			return nil, err
		}
	}

	// Add setup script if present
	if synthesis.SetupScript != "" {
		if err := addToTar(tw, "setup.sh", []byte(synthesis.SetupScript)); err != nil {
			return nil, err
		}
	}

	// Add source code based on source type
	switch req.SourceType {
	case SourceInline:
		// Determine filename from language
		filename := GetSourceFilename(synthesis.BaseImage, synthesis.RunCommand)
		if err := addToTar(tw, filename, []byte(req.SourceContent)); err != nil {
			return nil, err
		}

	default:
		// For other types, use generic filename
		if err := addToTar(tw, "code", []byte(req.SourceContent)); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}

	return &buf, nil
}

// addToTar adds a file to a tar archive
func addToTar(tw *tar.Writer, name string, content []byte) error {
	header := &tar.Header{
		Name:    name,
		Size:    int64(len(content)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	// Make scripts executable
	if strings.HasSuffix(name, ".sh") {
		header.Mode = 0755
	}

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header for %s: %w", name, err)
	}

	if _, err := tw.Write(content); err != nil {
		return fmt.Errorf("failed to write tar content for %s: %w", name, err)
	}

	return nil
}

// Cleanup removes a built image
func (b *Builder) Cleanup(ctx context.Context, imageID string) error {
	_, err := b.docker.ImageRemove(ctx, imageID, image.RemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
	return err
}

// Close closes the Docker client connection
func (b *Builder) Close() error {
	return b.docker.Close()
}
