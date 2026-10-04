package httpserve

import (
	"errors"
	"mime"
	"net/http"
)

func page(title, text string) []byte {
	return []byte(`<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">` +
		`<title>` + title + `</title><link rel="stylesheet" href="/public/css/app.css">` +
		`<link rel="icon" href="data:,"></head><body><div class="auth-wrap"><div class="auth-card">` +
		`<h1>` + title + `</h1>` + text + `</div></div></body></html>`)
}

var (
	brokenUpload = page("Файл не дошёл до шлюза целиком",
		`<p>Связь прервалась во время загрузки или браузер не смог прочитать файл.</p><p>Вернитесь назад и выберите файл ещё раз.</p>`)
	largeUpload = page("Файл слишком большой",
		`<p>Это не файл, который принимает панель: копия настроек и файл подключения намного меньше.</p><p>Вернитесь назад и проверьте, что выбран нужный файл.</p>`)
)

func Multipart(next http.Handler, maxFile int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt == "multipart/form-data" && r.ContentLength != 0 {
			r.Body = http.MaxBytesReader(w, r.Body, 2*maxFile)
			if err := r.ParseMultipartForm(maxFile); err != nil { //nolint:gosec
				code, body := http.StatusBadRequest, brokenUpload
				var tooBig *http.MaxBytesError
				if errors.As(err, &tooBig) {
					code, body = http.StatusRequestEntityTooLarge, largeUpload
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(code)
				_, _ = w.Write(body)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
