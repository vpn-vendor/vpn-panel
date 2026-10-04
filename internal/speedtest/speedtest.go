package speedtest

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

type Source struct {
	Name string
	URL  string
}

var DownSources = []Source{
	{Name: "Cloudflare", URL: "https://speed.cloudflare.com/__down?bytes=50000000"},
	{Name: "Vultr (Франкфурт)", URL: "https://fra-de-ping.vultr.com/vultr.com.100MB.bin"},
	{Name: "Vultr (Амстердам)", URL: "https://ams-nl-ping.vultr.com/vultr.com.100MB.bin"},
}

var UpSource = Source{Name: "Cloudflare", URL: "https://speed.cloudflare.com/__up"}

const (
	streamsPerSource = 4
	perSourceTime    = 8 * time.Second
	uploadChunkBytes = 4 << 20
)

type SourceResult struct {
	Name string `json:"name"`
	Kbit int    `json:"kbit"`
}

type Result struct {
	Down       []SourceResult `json:"down"`
	Up         []SourceResult `json:"up"`
	DownKbit   int            `json:"down_kbit"`
	UpKbit     int            `json:"up_kbit"`
	Divergent  bool           `json:"divergent"`
	MeasuredAt time.Time      `json:"measured_at"`
}

const DivergentPct = 20

type Client struct {
	HTTP *http.Client

	Sources       []Source
	Upload        Source
	PerSourceTime time.Duration
}

func New() *Client {
	return &Client{
		HTTP:          &http.Client{Timeout: perSourceTime + 10*time.Second},
		Sources:       DownSources,
		Upload:        UpSource,
		PerSourceTime: perSourceTime,
	}
}

func (c *Client) Measure(ctx context.Context) (*Result, error) {
	res := &Result{MeasuredAt: time.Now()}
	for _, s := range c.Sources {
		kbit := c.measureDown(ctx, s)
		res.Down = append(res.Down, SourceResult{Name: s.Name, Kbit: kbit})
	}
	res.DownKbit = median(res.Down)
	res.Divergent = divergent(res.Down)

	upKbit := c.measureUp(ctx)
	res.Up = append(res.Up, SourceResult{Name: c.Upload.Name, Kbit: upKbit})
	res.UpKbit = upKbit

	if res.DownKbit == 0 && res.UpKbit == 0 {
		return nil, errors.New("ни один источник замера недоступен — проверьте интернет или введите скорость из договора")
	}
	return res, nil
}

func (c *Client) MeasureDown(ctx context.Context) (*Result, error) {
	res := &Result{MeasuredAt: time.Now()}
	for _, s := range c.Sources {
		kbit := c.measureDown(ctx, s)
		res.Down = append(res.Down, SourceResult{Name: s.Name, Kbit: kbit})
	}
	res.DownKbit = median(res.Down)
	res.Divergent = divergent(res.Down)
	if res.DownKbit == 0 {
		return res, errors.New("ни один источник замера не ответил")
	}
	return res, nil
}

func (c *Client) measureDown(ctx context.Context, s Source) int {
	ctx, cancel := context.WithTimeout(ctx, c.PerSourceTime)
	defer cancel()

	var mu sync.Mutex
	var totalBytes int64
	start := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < streamsPerSource; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
			if err != nil {
				return
			}
			resp, err := c.HTTP.Do(req)
			if err != nil {
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				return
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			mu.Lock()
			totalBytes += n
			mu.Unlock()
		}()
	}
	wg.Wait()
	return kbitPerSec(totalBytes, time.Since(start))
}

func (c *Client) measureUp(ctx context.Context) int {
	ctx, cancel := context.WithTimeout(ctx, c.PerSourceTime)
	defer cancel()

	chunk := make([]byte, uploadChunkBytes)
	if _, err := rand.Read(chunk); err != nil {
		return 0
	}

	var mu sync.Mutex
	var totalBytes int64
	start := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < streamsPerSource; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Upload.URL, newChunkReader(chunk))
				if err != nil {
					return
				}
				req.ContentLength = int64(len(chunk))
				resp, err := c.HTTP.Do(req)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return
				}
				mu.Lock()
				totalBytes += int64(len(chunk))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return kbitPerSec(totalBytes, time.Since(start))
}

func newChunkReader(chunk []byte) io.Reader {
	cp := make([]byte, len(chunk))
	copy(cp, chunk)
	return &sliceReader{data: cp}
}

type sliceReader struct {
	data []byte
	off  int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func kbitPerSec(bytes int64, d time.Duration) int {
	if bytes <= 0 {
		return 0
	}
	ms := int64(d / time.Millisecond)
	if ms <= 0 {
		ms = 1
	}
	return int(bytes * 8 / ms)
}

func median(rs []SourceResult) int {
	var vals []int
	for _, r := range rs {
		if r.Kbit > 0 {
			vals = append(vals, r.Kbit)
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Ints(vals)
	mid := len(vals) / 2
	if len(vals)%2 == 1 {
		return vals[mid]
	}
	return (vals[mid-1] + vals[mid]) / 2
}

func divergent(rs []SourceResult) bool {
	minV, maxV := 0, 0
	for _, r := range rs {
		if r.Kbit <= 0 {
			continue
		}
		if minV == 0 || r.Kbit < minV {
			minV = r.Kbit
		}
		if r.Kbit > maxV {
			maxV = r.Kbit
		}
	}
	if minV == 0 {
		return false
	}
	return (maxV-minV)*100 > minV*DivergentPct
}

func FormatMbit(kbit int) string { return fmt.Sprintf("%d Мбит/с", kbit/1000) }
