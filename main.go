package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gehaxelt/ds_store"
)

type File struct {
	FileName   string
	StatusCode int
}

type Result struct {
	URL   string
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
	Timeout    int
	MaxDepth   int
	domainChan chan string
	jobChan    chan Job
	resultChan chan Result
}

type DSStore struct {
	Data       []byte
	StatusCode int
}

type Job struct {
	Domain string
	Depth  int
	Parent *DSStore
}

func (job *Job) scanDomain(ps *Parameters, addWork func(Job)) {

	if job.Depth == ps.MaxDepth {
		return
	}

	var err error
	found := true
	files := make([]File, 0)
	url := prepareUrl(ps, job.Domain)
	dsstore := downloadDS_Store(ps, url+".DS_Store")
	if dsstore == nil || dsstore.Data == nil || len(dsstore.Data) == 0 {
		ps.resultChan <- Result{
			URL:   url,
			Found: false,
			Files: files,
		}
		return
	}

	if job.Parent != nil && string(job.Parent.Data) == string(dsstore.Data) {
		return
	}

	if ps.listFiles {
		files, err = parseDS_Store(dsstore.Data)
		if err != nil {
			found = false
		}
	}

	if ps.listFiles && ps.statusCode {
		checkOnlineStatus(ps, url, &files)
	}

	if ps.recursive {
		var rekFiles []File

		if files != nil && len(files) == 0 {
			rekFiles, _ = parseDS_Store(dsstore.Data)
		} else {
			rekFiles = files
		}

		if rekFiles != nil {
			for _, file := range rekFiles {
				if file.StatusCode == 404 || dsstore.StatusCode == 404 {
					continue
				}
				var i int
				if ps.statusCode {
					i = file.StatusCode
				} else {
					i = dsstore.StatusCode
				}
				if !isDir(file, i) {
					continue
				}

				addWork(Job{Domain: url + file.FileName, Depth: job.Depth + 1, Parent: dsstore})
			}
		}
	}

	ps.resultChan <- Result{
		URL:   url,
		Found: found,
		Files: files,
	}
}

func isDir(file File, StatusCode int) (ok bool) {
	if StatusCode == 403 {
		return true
	}
	if StatusCode == 200 {
		if hasSlash(file.FileName) {
			return true
		} else if !strings.Contains(file.FileName, ".") {
			return true
		}
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
	if len(url) == 0 {
		return false
	}
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

func downloadDS_Store(ps *Parameters, url string) (dsstore *DSStore) {
	dsstore = &DSStore{StatusCode: -1}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := ps.Client.Do(req)
	if err != nil {
		if resp != nil {
			dsstore.StatusCode = resp.StatusCode
			return dsstore
		}
		return nil
	}

	dsstore.StatusCode = resp.StatusCode
	defer resp.Body.Close()

	defer func() {
		//https://stackoverflow.com/questions/25025467/catching-panics-in-golang
		// recover from panic if one occured. Set err to nil otherwise.
		if recover() != nil {
			err = errors.New("DS_Store parsing error")
		}
	}()

	dsstore.Data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	if len(dsstore.Data) < 8 {
		return nil
	}

	//magic number 0 0 0 1
	if dsstore.Data[0] != 0x0 && dsstore.Data[1] != 0x0 && dsstore.Data[2] != 0x0 && dsstore.Data[3] != 0x1 {
		return nil
	}

	//magic number 42 75 64 31
	if dsstore.Data[4] != 0x42 && dsstore.Data[5] != 0x75 && dsstore.Data[6] != 0x64 && dsstore.Data[7] != 0x31 {
		return nil
	}

	return dsstore
}

func parseDS_Store(data []byte) (files []File, err error) {
	if data == nil || len(data) < 32 {
		return nil, errors.New("No data")
	}
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
	flag.IntVar(&ps.MaxDepth, "d", 7, "Maximum recursion depth")
	flag.StringVar(&ps.DomainList, "i", "", "Path to domain list")
	flag.BoolVar(&ps.Https, "s", false, "Use SSL (HTTPS) connection")
	flag.BoolVar(&ps.Verbose, "v", false, "Verbose output (errors)")
	flag.BoolVar(&ps.listFiles, "l", false, "Parse .DS_Store and list files")
	flag.BoolVar(&ps.extendUrl, "e", false, "Preprend the URL to found files. Implies -l")
	flag.BoolVar(&ps.statusCode, "c", false, "Send HEAD request and show status code. Implies -l")
	flag.BoolVar(&ps.recursive, "r", false, "Recursively scan directories for .DS_Store.")

	flag.Parse()

	if ps.Threads < 0 {
		fmt.Println("Threads (-t): Invalid value:", ps.Threads)
		corrrectFlags = false
	}

	if ps.Timeout < 0 {
		fmt.Println("Timeout (-q): Invalid value:", ps.Timeout)
		corrrectFlags = false
	}

	if ps.MaxDepth <= 0 {
		fmt.Println("MaxDepth (-d): Invalid value:", ps.MaxDepth)
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
				Dial:                NewDialTimeout(timeout),
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

	ps.jobChan = make(chan Job)
	ps.resultChan = make(chan Result)
	var addWork func(Job)

	workerPool := new(sync.WaitGroup)
	//workerPool.Add(ps.Threads)
	printerPool := new(sync.WaitGroup)
	printerPool.Add(1)

	for i := 0; i < ps.Threads; i++ {
		go func() {
			for job := range ps.jobChan {
				job.scanDomain(&ps, addWork)
				workerPool.Done()
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

	// how to queue a job
	addWork = func(job Job) {
		workerPool.Add(1)
		select {
		case ps.jobChan <- job: // another worker took it
		default: // no free worker; do the job now
			job.scanDomain(&ps, addWork)
			workerPool.Done()
		}
	}

	lineScanner := bufio.NewScanner(domainListFile)
	for lineScanner.Scan() {
		domain := lineScanner.Text()
		//ps.domainChan <- domain
		addWork(Job{Domain: domain})
	}

	workerPool.Wait()
	close(ps.jobChan)
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
