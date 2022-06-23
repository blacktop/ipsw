package s3

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3 struct {
	client *minio.Client
	bucket string
}

func NewClient(endpoint, accessKeyID, secretAccessKey string, useSSL bool) (*S3, error) {
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
	ctx := context.Background()

	if exists, err := s.client.BucketExists(ctx, bucketName); err != nil {
		return fmt.Errorf("failed to check if bucket %s exists: %v", bucketName, err)
	} else if !exists {
		if err := s.client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{}); err != nil {
			return fmt.Errorf("failed to make bucket %s: %v", bucketName, err)
		}
		log.Debugf("Successfully created %s", bucketName)
	}

	ct, err := getContentType(filePath)
	if err != nil {
		return fmt.Errorf("failed to get mime type for file %s: %v", filePath, err)
	}

	// Upload the file
	info, err := s.client.FPutObject(ctx, bucketName, filepath.Base(filePath), filePath, minio.PutObjectOptions{ContentType: ct})
	if err != nil {
		return fmt.Errorf("failed to upload %s: %v", filePath, err)
	}

	log.Debugf("Successfully uploaded %s of size %d", filePath, info.Size)

	return nil
}

func (s *S3) Get(srcObject, destPath, bucketName string) error {

	if err := s.client.FGetObject(context.Background(), bucketName, srcObject, destPath, minio.GetObjectOptions{}); err != nil {
		return fmt.Errorf("failed to get file %s: %v", srcObject, err)
	}

	return nil
}
