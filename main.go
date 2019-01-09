package main

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"
)

func main() {

	http.Handle("/", &templateHandler{filename: "login.html"})
	http.Handle("/user", MustAuth(&templateHandler{filename: "user.html"}))

	http.HandleFunc("/auth/", loginHandler)

	if err := http.ListenAndServe(":4000", nil); err != nil {
		log.Fatal("ListenAndServe:", err)
	}

}

// templateHandler represents a single template
type templateHandler struct {
	filename string
	templ    *template.Template
}

func (t *templateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if t.templ == nil {
		t.templ = template.Must(template.ParseFiles(filepath.Join("templates", t.filename)))
	}

	data := map[string]interface{}{}
	if authCookie, err := r.Cookie("auth"); err == nil {
		data["ID"] = authCookie.Value
	}

	t.templ.Execute(w, data)
}
