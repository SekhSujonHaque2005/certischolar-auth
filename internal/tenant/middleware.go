package tenant

import (
	"log"
	"net/http"
)

// Middleware ensures all requests carry appropriate tenant isolation headers
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			tenantID = "lpu-main" // Default university tenant context
		}
		
		// Set CORS headers for multi-portal access
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		log.Printf("[%s] %s (Tenant: %s)", r.Method, r.URL.Path, tenantID)
		next.ServeHTTP(w, r)
	})
}
