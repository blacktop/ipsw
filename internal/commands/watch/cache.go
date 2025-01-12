package watch

import (
	"bufio"
	"os"
	"path/filepath"

	"github.com/apex/log"
	lru "github.com/hashicorp/golang-lru/v2"
)

type WatchCache interface {
	Add(key string, value any)
	Get(key string) (any, bool)
}

type MemoryCache struct {
	cache *lru.Cache[string, any]
}

type FileCache struct {
	path string
}

func NewMemoryCache(size int) (*MemoryCache, error) {
	lcache, err := lru.New[string, any](size)
	if err != nil {
		return nil, err
	}
	return &MemoryCache{
		cache: lcache,
	}, nil
}

func (c *MemoryCache) Add(key string, value any) {
	c.cache.Add(key, value)
}

func (c *MemoryCache) Get(key string) (any, bool) {
	return c.cache.Get(key)
}

func NewFileCache(path string) (*FileCache, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	// Check if file exists, create it if it doesn't
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		f.Close()
	}

	return &FileCache{
		path: path,
	}, nil
}

func (c *FileCache) Add(key string, value any) {
	file, err := os.OpenFile(c.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if _, err := file.WriteString(key + "\n"); err != nil {
		log.WithError(err).Error("failed to write to cache")
	}
}

func (c *FileCache) Get(key string) (any, bool) {
	file, err := os.OpenFile(c.path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() == key {
			return nil, true
		}
	}
	if err := scanner.Err(); err != nil {
		log.WithError(err).Error("failed to read from cache")
	}
	return nil, false
}
