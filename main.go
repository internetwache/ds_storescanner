package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/gehaxelt/ds_store"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"strings"
	"time"
	"net"
)

type File struct {
	FileName   string
	StatusCode int
}

type Result struct {
	URL   string
	Data  []byte
	Found bool
	Files []File
}

type Parameters struct {
	Threads    int
	DomainList string
	Verbose    bool
	Https      bool
	listFiles  bool
	extendUrl  bool
	statusCode bool
	recursive  bool
	Client     *http.Client
	Timeout		int
	domainChan	chan string
	resultChan  chan Result
}

func scanDomain(ps *Parameters, domain string) {

	var err error
	found := true
	files := make([]File, 0)
	url := prepareUrl(ps, domain)
	data := downloadDS_Store(ps, url+".DS_Store")
	if data == nil {
		found = false
	}

	if ps.listFiles {
		files, err = parseDS_Store(data)
		if err != nil {
			found = false
		}
	}

	if ps.recursive {
		var rekFiles []File
		
		if files != nil && len(files) == 0 {
			rekFiles, err = parseDS_Store(data)
		} else {
			rekFiles = files
		}
		
		if rekFiles != nil {
			for _, file := range rekFiles {
				if ! isDir(file) {
					continue
				}
				ps.domainChan <- url + file.FileName
			}
		}
	}

	if ps.listFiles && ps.statusCode {
		checkOnlineStatus(ps, url, &files)
	}

	ps.resultChan <- Result{
		URL:   url,
		Found: found,
		Data:  data,
		Files: files,
	}
}

func isDir(file File) (ok bool) {
	if file.StatusCode == -1 && ! strings.Contains(file.FileName, ".") {
		return true
	}
	if file.StatusCode == 200 && ! strings.Contains(file.FileName, ".") {
		return true
	}
	if file.StatusCode == 403 {
		return true
	}
	return false
}

func prepareUrl(ps *Parameters, domain string) string {
	url := ""

	if hasProtocol(domain, ps.Https) == false {
		url += "http"
		if ps.Https {
			url += "s"
		}
		url += "://"
	}

	url += domain

	if hasSlash(url) == false {
		url += "/"
	}

	return url
}

func hasSlash(url string) bool {
	c := url[len(url)-1:]

	if c == "/" {
		return true
	}

	return false
}

func hasProtocol(url string, https bool) bool {
	if len(url) < 8 {
		return false
	}

	if url[:8] == "https://" || url[:7] == "http://" {
		return true
	}

	return false
}

func downloadDS_Store(ps *Parameters, url string) []byte {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := ps.Client.Do(req)
	if err != nil {
		return nil
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	if len(body) < 8 {
		return nil
	}

	//magic number 0 0 0 1
	if body[0] != 0x0 && body[1] != 0x0 && body[2] != 0x0 && body[3] != 0x1 {
		return nil
	}

	//magic number 42 75 64 31
	if body[4] != 0x42 && body[5] != 0x75 && body[6] != 0x64 && body[7] != 0x31 {
		return nil
	}

	return body
}

func parseDS_Store(data []byte) (files []File, err error) {
	a, err := ds_store.NewAllocator(data)
	if err != nil {
		return nil, errors.New("Failed to parse .DS_Store file")
	}

	fileNames, err := a.TraverseFromRootNode()
	if err != nil {
		return nil, errors.New("Failed to parse .DS_Store file")
	}

	for _, fileName := range fileNames {
		if !contains(files, fileName) {
			files = append(files, File{FileName: fileName, StatusCode: -1})
		}
	}

	return files, nil

}

func contains(files []File, fileName string) (ok bool) {
	for _, file := range files {
		if file.FileName == fileName {
			return true
		}
	}
	return false
}

func checkOnlineStatus(ps *Parameters, url string, files *[]File) {
	for idx, _ := range *files {
		fileUrl := url + (*files)[idx].FileName
		(*files)[idx].StatusCode = sendHeadRequest(ps, fileUrl)
	}
}

func sendHeadRequest(ps *Parameters, url string) (statusCode int) {
	statusCode = -1

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return statusCode
	}

	resp, err := ps.Client.Do(req)
	if err != nil {
		if resp != nil {
			return resp.StatusCode
		}
		return statusCode
	}
	defer resp.Body.Close()

	statusCode = resp.StatusCode

	return statusCode
}

func printResult(ps *Parameters, r *Result) {
	output := ""

	if ps.Verbose {
		if r.Found {
			output += "Found : "
		} else {
			output += "Missed: "
		}
	}

	if r.Found || ps.Verbose {
		output += r.URL
		fmt.Println(output)
	}

	if r.Found && ps.listFiles && r.Files != nil {
		for _, file := range r.Files {

			if ps.extendUrl {
				fmt.Printf("-> %s%s", r.URL, file.FileName)
			} else {
				fmt.Printf("-> %s", file.FileName)
			}

			if ps.statusCode {
				fmt.Printf(" (%d)", file.StatusCode)
			}

			fmt.Printf("\n")
		}
	}
}

func main() {

	ps := Parameters{}
	corrrectFlags := true

	flag.IntVar(&ps.Threads, "t", 10, "Number of concurrent threads")
	flag.IntVar(&ps.Timeout, "q", 10, "Timeout in seconds")
	flag.StringVar(&ps.DomainList, "i", "", "Path to domain list")
	flag.BoolVar(&ps.Https, "s", false, "Use SSL (HTTPS) connection")
	flag.BoolVar(&ps.Verbose, "v", false, "Verbose output (errors)")
	flag.BoolVar(&ps.listFiles, "l", false, "Parse .DS_Store and list files")
	flag.BoolVar(&ps.extendUrl, "e", false, "Preprend the URL to found files. Implies -l")
	flag.BoolVar(&ps.statusCode, "c", false, "Send HEAD request and show status code. Implies -l")
	flag.BoolVar(&ps.recursive, "r", false, "Recursively scan directories for .DS_Store")

	flag.Parse()

	if ps.Threads < 0 {
		fmt.Println("Threads (-t): Invalid value:", ps.Threads)
		corrrectFlags = false
	}

	if ps.Timeout < 0 {
		fmt.Println("Timeout (-q): Invalid value:", ps.Timeout)
		corrrectFlags = false
	}

	if ps.DomainList == "" {
		fmt.Println("DomainList (-i): Must be specified")
		corrrectFlags = false
	} else if _, err := os.Stat(ps.DomainList); os.IsNotExist(err) {
		fmt.Println("DomainList (-i): File does not exist:", ps.DomainList)
		corrrectFlags = false
	}

	if ps.extendUrl || ps.statusCode {
		ps.listFiles = true
	}

	if corrrectFlags {
		timeout := time.Duration(time.Duration(uint32(ps.Timeout)) * time.Second)
		ps.Client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				Dial: NewDialTimeout(timeout),
				DisableKeepAlives:   true,
				MaxIdleConnsPerHost: 50,
			},
		}
	} else {
		panic("Flag parsing failed!")
	}

	domainListFile, err := os.Open(ps.DomainList)
	if err != nil {
		panic("Failed to open domainlist")
	}

	ps.domainChan = make(chan string, ps.Threads)
	ps.resultChan = make(chan Result)

	workerPool := new(sync.WaitGroup)
	workerPool.Add(ps.Threads)
	printerPool := new(sync.WaitGroup)
	printerPool.Add(1)

	for i := 0; i < ps.Threads; i++ {
		go func() {
			defer workerPool.Done()
			for {
				domain := <-ps.domainChan

				if domain == "" {
					break
				}

				scanDomain(&ps, domain)
			}
		}()
	}

	go func() {
		defer printerPool.Done()
		for r := range ps.resultChan {
			printResult(&ps, &r)
		}
	}()

	defer domainListFile.Close()

	lineScanner := bufio.NewScanner(domainListFile)
	for lineScanner.Scan() {
		domain := lineScanner.Text()
		ps.domainChan <- domain
	}

	close(ps.domainChan)
	workerPool.Wait()
	close(ps.resultChan)
	printerPool.Wait()
}

//Inspired by http://stackoverflow.com/questions/16895294/how-to-set-timeout-for-http-get-requests-in-golang#
func NewDialTimeout(timeout time.Duration) func(net, addr string) (c net.Conn, err error) {
    return func(netw, addr string) (net.Conn, error) {
        conn, err := net.DialTimeout(netw, addr, timeout)
        if err != nil {
            return nil, err
        }
        conn.SetDeadline(time.Now().Add(timeout))
        return conn, nil
    }
}