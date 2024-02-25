package opaal

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

type Server struct {
	http.Server
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

func NewServerWithConfig(config *Config) *Server {
	host := config.Server.Host
	port := config.Server.Port
	server := &Server{
		Host: host,
		Port: port,
	}
	server.Addr = fmt.Sprintf("%s:%d", host, port)
	return server
}

func (s *Server) SetListenAddr(host string, port int) {
	s.Host = host
	s.Port = port
	s.Addr = s.GetListenAddr()
}

func (s *Server) GetListenAddr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func (s *Server) WaitForAuthorizationCode(loginUrl string) (string, error) {
	var code string
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// show login page with notice to redirect
		loginPage, err := os.ReadFile("pages/index.html")
		if err != nil {
			fmt.Printf("failed to load login page: %v\n", err)
		}
		loginPage = []byte(strings.ReplaceAll(string(loginPage), "{{loginUrl}}", loginUrl))
		w.WriteHeader(http.StatusSeeOther)
		w.Write(loginPage)
	})
	http.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		// get the code from the OIDC provider
		if r != nil {
			code = r.URL.Query().Get("code")
			fmt.Printf("Authorization code: %v\n", code)
		}
		http.Redirect(w, r, s.Addr+"/success", http.StatusSeeOther)
		s.Close()
	})
	return code, s.ListenAndServe()
}

func (s *Server) ShowSuccessPage() error {
	http.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {

	})
	return s.ListenAndServe()
}
