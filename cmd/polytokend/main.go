package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"polytoken/internal/config"
	"polytoken/internal/middleware"
	"polytoken/internal/resolver"
	"polytoken/internal/validator"
	"syscall"
	"time"
)

func main() {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	validators, err := validator.BuildValidators(cfg.Issuers)
	if err != nil {
		log.Fatal(err)
	}

	res := resolver.NewResolver(validators)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	auth := middleware.Authenticate(res)
	mux.Handle("GET /whoami", auth(http.HandlerFunc(whoami)))

	srv := &http.Server{Addr: ":8080", Handler: mux}

	// server runs in background so main can wait for a signal
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	log.Println("listening on :8080")

	// block until SIGINT/SIGTERM
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")

	// give in-flight requests up to 10s to finish
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	log.Println("stopped")
}
