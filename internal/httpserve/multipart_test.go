package httpserve

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func form(t *testing.T) (*bytes.Buffer, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("_csrf", "токен")
	f, _ := w.CreateFormFile("file", "copy.vpnpanel")
	_, _ = f.Write(bytes.Repeat([]byte("x"), 4096))
	_ = w.Close()
	return &b, w.FormDataContentType()
}

func TestMultipartParsedBeforeHandler(t *testing.T) {
	body, ct := form(t)
	var seen bool
	h := Multipart(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.MultipartForm != nil && r.PostForm.Get("_csrf") == "токен" && len(r.MultipartForm.File["file"]) == 1
	}), 1<<13)
	req := httptest.NewRequest(http.MethodPost, "/backup/import", body)
	req.Header.Set("Content-Type", ct)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !seen {
		t.Fatal("обработчик не получил разобранную форму")
	}
}

func TestMultipartBrokenBodyRefused(t *testing.T) {
	body, ct := form(t)
	cut := body.Bytes()[:body.Len()/2]
	called := false
	h := Multipart(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), 1<<13)
	req := httptest.NewRequest(http.MethodPost, "/backup/import", io.NopCloser(bytes.NewReader(cut)))
	req.Header.Set("Content-Type", ct)
	req.ContentLength = int64(body.Len())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called || rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "не дошёл") {
		t.Fatalf("оборванная форма: код %d, обработчик %v", rec.Code, called)
	}
}

func TestMultipartTooLargeRefused(t *testing.T) {
	body, ct := form(t)
	called := false
	h := Multipart(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), int64(body.Len()/4))
	req := httptest.NewRequest(http.MethodPost, "/backup/import", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called || rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "слишком большой") {
		t.Fatalf("большое тело: код %d, обработчик %v", rec.Code, called)
	}
}
