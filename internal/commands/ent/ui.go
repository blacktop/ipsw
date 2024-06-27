package ent

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apex/log"
)

// TODO: gzip static files
var (
	//go:embed templates
	templatesFs embed.FS

	//go:embed templates/static
	staticFiles embed.FS
)

type page struct {
	Version string
	DB      map[string]string
}

func UI(db map[string]string, c *Config) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFS(templatesFs, "templates/page.html")
		if err != nil {
			log.Errorf("failed to parse the template: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := tmpl.ExecuteTemplate(w, "page.html", page{
			Version: c.Version,
			DB:      db,
		}); err != nil {
			log.Errorf("failed to execute the template: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})

	staticFs, err := fs.Sub(staticFiles, "templates/static")
	if err != nil {
		return err
	}

	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFs))))

	addr := fmt.Sprintf(":%d", c.Port)
	if c.Host != "localhost" {
		addr = fmt.Sprintf("%s:%d", c.Host, c.Port)
	}

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.WithFields(log.Fields{
		"host": c.Host,
		"port": c.Port,
	}).Info("Starting Server")
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: failed to listen and serve: %v\n", err)
		}
		log.Warn("shutting down server...")
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownRelease()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("server: failed to shutdown: %v", err)
	}
	log.Info("Shutdown Complete")

	return nil
}
