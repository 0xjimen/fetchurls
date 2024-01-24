package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	var domains []string

	var dates bool
	flag.BoolVar(&dates, "dates", false, "show date of fetch in the first column")

	var noSubs bool
	flag.BoolVar(&noSubs, "no-subs", false, "don't include subdomains of the target domain")

	var getVersionsFlag bool
	flag.BoolVar(&getVersionsFlag, "get-versions", false, "list URLs for crawled versions of input URL(s)")

	flag.Parse()

	if flag.NArg() > 0 {
		// fetch for a single domain
		domains = []string{flag.Arg(0)}
	} else {
		// fetch for all domains from stdin
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			domains = append(domains, sc.Text())
		}

		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	// get-versions mode
	if getVersionsFlag {
		for _, u := range domains {
			versions, err := getVersions(u)
			if err != nil {
				continue
			}
			fmt.Println(strings.Join(versions, "\n"))
		}
		return
	}

	fetchFns := []fetchFn{
		getWaybackURLs,
		getCommonCrawlURLs,
		getVirusTotalURLs,
	}

	for _, domain := range domains {
		var wg sync.WaitGroup
		wurls := make(chan wurl)
		seen := make(map[string]bool)
		mu := &sync.Mutex{}

		for _, fn := range fetchFns {
			wg.Add(1)
			fetch := fn
			go func() {
				defer wg.Done()
				resp, err := fetch(domain, noSubs)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error fetching data: %v\n", err)
					return
				}
				for _, r := range resp {
					mu.Lock()
					if !seen[r.url] {
						seen[r.url] = true
						mu.Unlock()
						wurls <- r
					} else {
						mu.Unlock()
					}
				}
			}()
		}

		go func() {
			wg.Wait()
			close(wurls)
		}()

		for w := range wurls {
			if dates {
				d, err := time.Parse("20060102150405", w.date)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to parse date [%s] for URL [%s]\n", w.date, w.url)
				}
				fmt.Printf("%s %s\n", d.Format(time.RFC3339), w.url)
			} else {
				fmt.Println(w.url)
			}
		}
	}
}

type wurl struct {
	date string
	url  string
}

type fetchFn func(string, bool) ([]wurl, error)

func fetch(domain string, noSubs bool) ([]wurl, error) {
	//subsWildcard := getSubsWildcard(noSubs)
	var wg sync.WaitGroup
	wurls := make(chan wurl)
	seen := make(map[string]bool)
	mu := &sync.Mutex{}

	fetchFns := []fetchFn{
		getWaybackURLs,
		getCommonCrawlURLs,
		getVirusTotalURLs,
	}

	for _, fn := range fetchFns {
		wg.Add(1)
		fetch := fn
		go func() {
			defer wg.Done()
			resp, err := fetch(domain, noSubs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching data: %v\n", err)
				return
			}
			for _, r := range resp {
				mu.Lock()
				if !seen[r.url] {
					seen[r.url] = true
					mu.Unlock()
					wurls <- r
				} else {
					mu.Unlock()
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(wurls)
	}()

	out := make([]wurl, 0)
	for w := range wurls {
		out = append(out, w)
	}
	return out, nil
}

func getWaybackURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := getSubsWildcard(noSubs)
	res, err := http.Get(fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsWildcard, domain))
	if err != nil {
		return nil, err
	}

	raw, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}

	var wrapper [][]string
	err = json.Unmarshal(raw, &wrapper)
	if err != nil {
		return nil, err
	}

	out := make([]wurl, 0, len(wrapper))
	skip := true

	for _, urls := range wrapper {
		if skip {
			skip = false
			continue
		}
		out = append(out, wurl{date: urls[1], url: urls[2]})
	}

	return out, nil
}

func getCommonCrawlURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := getSubsWildcard(noSubs)
	res, err := http.Get(fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", subsWildcard, domain))
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)

	out := make([]wurl, 0)
	for sc.Scan() {
		wrapper := struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}{}
		err = json.Unmarshal([]byte(sc.Text()), &wrapper)
		if err != nil {
			continue
		}
		out = append(out, wurl{date: wrapper.Timestamp, url: wrapper.URL})
	}

	return out, nil
}

func getVirusTotalURLs(domain string, noSubs bool) ([]wurl, error) {
	out := make([]wurl, 0)

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return out, nil
	}

	fetchURL := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", apiKey, domain)
	resp, err := http.Get(fetchURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	wrapper := struct {
		URLs []struct {
			URL string `json:"url"`
		} `json:"detected_urls"`
	}{}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&

wrapper)

	for _, u := range wrapper.URLs {
		out = append(out, wurl{url: u.URL})
	}

	return out, nil
}

func isSubdomain(rawUrl, domain string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return false
	}
	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}

func getVersions(u string) ([]string, error) {
	out := make([]string, 0)
	resp, err := http.Get(fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s&output=json", u))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	r := [][]string{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&r)
	if err != nil {
		return nil, err
	}

	first := true
	seen := make(map[string]bool)
	for _, s := range r {
		if first {
			first = false
			continue
		}
		if seen[s[5]] {
			continue
		}
		seen[s[5]] = true
		out = append(out, fmt.Sprintf("https://web.archive.org/web/%sif_/%s", s[1], s[2]))
	}

	return out, nil
}

func getSubsWildcard(noSubs bool) string {
	if noSubs {
		return ""
	}
	return "*."
}

