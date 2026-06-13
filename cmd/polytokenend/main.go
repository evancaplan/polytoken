package main

import (
	"log"
	"net/http"
	"polytoken/internal/config"
	"polytoken/internal/middleware"
	"polytoken/internal/resolver"
	"polytoken/internal/validator"
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

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
