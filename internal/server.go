package opaal

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
)

type Server struct {
	*http.Server
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Callback string `yaml:"callback"`
}

func NewServerWithConfig(conf *Config) *Server {
	host := conf.Server.Host
	port := conf.Server.Port
	server := &Server{
		Server: &http.Server{
			Addr: fmt.Sprintf("%s:%d", host, port),
		},
		Host: host,
		Port: port,
	}
	return server
}

func (s *Server) SetListenAddr(host string, port int) {
	s.Addr = s.GetListenAddr()
}

func (s *Server) GetListenAddr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func (s *Server) WaitForAuthorizationCode(loginUrl string, callback string) (string, error) {
	// check if callback is set
	if callback == "" {
		callback = "/oidc/callback"
	}

	var code string
	r := chi.NewRouter()
	r.Use(middleware.RedirectSlashes)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// show login page with notice to redirect
		loginPage, err := os.ReadFile("pages/index.html")
		if err != nil {
			fmt.Printf("failed to load login page: %v\n", err)
		}
		loginPage = []byte(strings.ReplaceAll(string(loginPage), "{{loginUrl}}", loginUrl))
		w.Write(loginPage)
	})
	r.HandleFunc(callback, func(w http.ResponseWriter, r *http.Request) {
		// get the code from the OIDC provider
		if r != nil {
			code = r.URL.Query().Get("code")
			fmt.Printf("Authorization code: %v\n", code)
		}
		http.Redirect(w, r, "/redirect", http.StatusSeeOther)
	})
	r.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		err := s.Close()
		if err != nil {
			fmt.Printf("failed to close server: %v\n", err)
		}
	})
	s.Handler = r

	return code, s.ListenAndServe()
}

func (s *Server) Serve(data chan []byte) error {
	output, ok := <-data
	if !ok {
		return fmt.Errorf("failed to receive data")
	}

	fmt.Printf("Received data: %v\n", string(output))
	// http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {

	// })
	r := chi.NewRouter()
	r.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Serving success page.")
		successPage, err := os.ReadFile("pages/success.html")
		if err != nil {
			fmt.Printf("failed to load success page: %v\n", err)
		}
		successPage = []byte(strings.ReplaceAll(string(successPage), "{{access_token}}", string(output)))
		w.Write(successPage)
	})
	r.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Serving error page.")
		errorPage, err := os.ReadFile("pages/success.html")
		if err != nil {
			fmt.Printf("failed to load success page: %v\n", err)
		}
		// errorPage = []byte(strings.ReplaceAll(string(errorPage), "{{access_token}}", output))
		w.Write(errorPage)
	})

	s.Handler = r
	return s.ListenAndServe()
}
