package kv

import (
	"fmt"
	"path"
	"rvault/internal/pkg/api"
	"strings"
	"sync"

	vapi "github.com/hashicorp/vault/api"
	progressbar "github.com/schollz/progressbar/v3"
	"k8s.io/klog/v2"
)

func grep(c *vapi.Client, searchTerm string, engine string, secretPath string, kvVersion string,
	wg *sync.WaitGroup, res chan<- *readResult,
	throttleC chan struct{}) {
	defer wg.Done()
	var err error
	var secret *vapi.Secret
	pathPrefix, err := api.GetReadBasePath(engine, kvVersion)

	if err == nil {
		// If channel is buffered
		if cap(throttleC) > 0 {
			// Block here if channel is full
			throttleC <- struct{}{}
		}

		secret, err = c.Logical().Read(path.Join(pathPrefix, secretPath))

		// If channel is buffered
		if cap(throttleC) > 0 {
			// Signal API call done
			<-throttleC
		}
	}
	result := readResult{
		path:   secretPath,
		err:    err,
		secret: secret,
	}
	parsedSecret, errString := parseSecretData(result, kvVersion)
	if errString != "" {
		res <- &readResult{
			path:   secretPath,
			err:    fmt.Errorf(errString),
			secret: secret,
		}
		return
	}
	// fmt.Printf("%v\n", parsedSecret)
	for _, value := range parsedSecret {

		if strings.Contains(value, searchTerm) == true {
			res <- &readResult{
				path:   secretPath,
				err:    err,
				secret: secret,
			}
		} else {
			res <- nil
		}
	}

}

// RGrep searches all secrets for a given path including every subpath. No more than 'concurrency' API queries to Vault
// will be done.
func RGrep(c *vapi.Client, engine string, path string, includePaths []string, excludePaths []string,
	concurrency uint32, searchTerm string) (map[string]map[string]string, error) {
	// var searchHits []string
	var dumpResults []readResult
	kvVersion, err := getKVVersion(c, engine)
	if err != nil {
		return nil, err
	}

	wg := sync.WaitGroup{}
	resChan := make(chan *readResult)
	exitChan := make(chan struct{})
	throttleChan := make(chan struct{}, concurrency)
	klog.V(4).Info("Retrieving list of keys..")
	secretPaths, err := RList(c, engine, path, includePaths, excludePaths, concurrency)
	klog.V(4).Infof("Listing returned %d secret paths", len(secretPaths))
	fmt.Printf("Searching across %d secret paths\n", len(secretPaths))
	bar := progressbar.New(len(secretPaths))

	if err != nil {
		return nil, err
	}
	go func(dumpResults *[]readResult, resChan <-chan *readResult, exitC <-chan struct{}) {
		for {
			select {
			case res := <-resChan:
				bar.Add(1)
				if res != nil {
					*dumpResults = append(*dumpResults, *res)
				}
			case <-exitChan:
				return
			}
		}
	}(&dumpResults, resChan, exitChan)

	wg.Add(len(secretPaths))
	for _, secretPath := range secretPaths {
		go grep(c, searchTerm, engine, secretPath, kvVersion, &wg, resChan, throttleChan)
	}

	wg.Wait()
	// finish goroutine ensuring results are processed
	exitChan <- struct{}{}
	fmt.Println()
	// fmt.Printf("Shit: %+v\n", dumpResults)
	return parseReadResults(dumpResults, kvVersion)
	// for _, v := range dumpResults {
	// 	searchHits = append(fmt.Sprintf("searchHits, v)
	// }
	// return searchHits, nil
}
