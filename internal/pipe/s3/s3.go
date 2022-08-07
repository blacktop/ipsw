// Package s3 contains the s3 publisher pipe.
package s3

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/config"
	"github.com/blacktop/ipsw/internal/context"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"golang.org/x/sync/errgroup"
)

// Pipe for blobs.
type Pipe struct{}

// String returns the description of the pipe.
func (Pipe) String() string                 { return "s3" }
func (Pipe) Skip(ctx *context.Context) bool { return len(ctx.Config.S3) == 0 }

// Publish to specified blob bucket url.
func (Pipe) Publish(ctx *context.Context) error {
	var g errgroup.Group
	for _, conf := range ctx.Config.S3 {
		conf := conf
		g.Go(func() error {
			return doUpload(ctx, conf)
		})
	}
	return g.Wait()
}

func doUpload(ctx *context.Context, conf config.S3) error {
	client, err := NewClient(ctx, conf.Endpoint, conf.AccessKeyID, conf.SecretAccessKey, conf.UseSSL)
	if err != nil {
		return err
	}
	return client.Upload(conf.File, conf.Bucket)
}

type S3 struct {
	client *minio.Client
	bucket string
	ctx    *context.Context
}

func NewClient(ctx *context.Context, endpoint, accessKeyID, secretAccessKey string, useSSL bool) (*S3, error) {
	// Initialize minio client object.
	c, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create new S3 client: %v", err)
	}

	return &S3{
		client: c,
		bucket: "",
		ctx:    ctx,
	}, nil
}

func getContentType(filePath string) (string, error) {
	// Open file
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, 512)
	if _, err := f.Read(buf); err != nil {
		return "", fmt.Errorf("failed to read file magic: %v", err)
	}
	// lookup mime type
	return http.DetectContentType(buf), nil
}

func (s *S3) Upload(filePath, bucketName string) error {

	if exists, err := s.client.BucketExists(s.ctx, bucketName); err != nil {
		return fmt.Errorf("failed to check if bucket %s exists: %v", bucketName, err)
	} else if !exists {
		if err := s.client.MakeBucket(s.ctx, bucketName, minio.MakeBucketOptions{}); err != nil {
			return fmt.Errorf("failed to make bucket %s: %v", bucketName, err)
		}
		log.Debugf("Successfully created %s", bucketName)
	}

	ct, err := getContentType(filePath)
	if err != nil {
		return fmt.Errorf("failed to get mime type for file %s: %v", filePath, err)
	}

	// Upload the file
	info, err := s.client.FPutObject(s.ctx, bucketName, filepath.Base(filePath), filePath, minio.PutObjectOptions{ContentType: ct})
	if err != nil {
		return fmt.Errorf("failed to upload %s: %v", filePath, err)
	}

	log.Debugf("Successfully uploaded %s of size %d", filePath, info.Size)

	return nil
}

func (s *S3) Get(srcObject, destPath, bucketName string) error {

	if err := s.client.FGetObject(s.ctx, bucketName, srcObject, destPath, minio.GetObjectOptions{}); err != nil {
		return fmt.Errorf("failed to get file %s: %v", srcObject, err)
	}

	return nil
}
