package info

import (
	"encoding/json"
	"io/ioutil"
	"log"

	"github.com/gocolly/colly/v2"
)

// Processors stores information about processors
type Processors struct {
	Name          string
	Model         string
	Semiconductor string
	DieSize       string
	Transistors   string
	CPUISA        string
	CPU           string
	CPUCache      string
	GPU           string
	AIAccelerator string
	Memory        string
	Introduced    string
	Devices       string
}

// ScrapeURLs will scrape the iPhone Wiki for beta firmwares
func ScrapeURLs(build string) error {

	// Instantiate default collector
	c := colly.NewCollector(
		// Visit only domains: coursera.org, www.coursera.org
		colly.AllowedDomains("en.wikipedia.org", "www.en.wikipedia.org"),

		// Cache responses to prevent multiple download of pages
		// even if the collector is restarted
		colly.CacheDir("./wikipedia_cache"),
	)

	procs := make([]Processors, 0, 200)

	// Before making a request print "Visiting ..."
	c.OnRequest(func(r *colly.Request) {
		log.Println("visiting", r.URL.String())
	})

	// Extract details of the course
	// On every a HTML element which has name attribute call callback
	c.OnHTML(`table[class=wikitable]`, func(e *colly.HTMLElement) {

		var proc Processors
		// Iterate over rows of the table which contains different information
		// about the course
		e.ForEach("tr", func(_ int, el *colly.HTMLElement) {
			if len(el.ChildText("td:nth-child(2)")) == 0 {
				proc = Processors{
					Name:          "",
					Model:         el.ChildText("td:nth-child(1)"),
					Semiconductor: el.ChildText("td:nth-child(4)"),
					DieSize:       el.ChildText("td:nth-child(5)"),
					Transistors:   el.ChildText("td:nth-child(6)"),
					CPUISA:        el.ChildText("td:nth-child(7)"),
					CPU:           el.ChildText("td:nth-child(8)"),
					CPUCache:      el.ChildText("td:nth-child(9)"),
					GPU:           el.ChildText("td:nth-child(10)"),
					AIAccelerator: el.ChildText("td:nth-child(11)"),
					Memory:        el.ChildText("td:nth-child(12)"),
					Introduced:    el.ChildText("td:nth-child(13)"),
					Devices:       el.ChildText("td:nth-child(14)"),
				}
			} else {
				proc = Processors{
					Name:          el.ChildText("td:nth-child(1)"),
					Model:         el.ChildText("td:nth-child(2)"),
					Semiconductor: el.ChildText("td:nth-child(4)"),
					DieSize:       el.ChildText("td:nth-child(5)"),
					Transistors:   el.ChildText("td:nth-child(6)"),
					CPUISA:        el.ChildText("td:nth-child(7)"),
					CPU:           el.ChildText("td:nth-child(8)"),
					CPUCache:      el.ChildText("td:nth-child(9)"),
					GPU:           el.ChildText("td:nth-child(10)"),
					AIAccelerator: el.ChildText("td:nth-child(11)"),
					Memory:        el.ChildText("td:nth-child(12)"),
					Introduced:    el.ChildText("td:nth-child(13)"),
					Devices:       el.ChildText("td:nth-child(14)"),
					// Extra:         el.ChildText("td:nth-child(14)"),
				}
			}
			if len(el.ChildText("td:nth-child(14)")) == 0 {
				proc.Memory = el.ChildText("td:nth-child(11)")
				proc.Introduced = el.ChildText("td:nth-child(12)")
				proc.Devices = el.ChildText("td:nth-child(13)")
			}
			procs = append(procs, proc)
		})
	})

	// Start scraping on http://coursera.com/browse
	c.Visit("https://en.wikipedia.org/wiki/Apple-designed_processors")

	c.Wait()

	procsJSON, err := json.MarshalIndent(procs, "", "    ")
	if err != nil {
		return err
	}
	ioutil.WriteFile("procs.json", procsJSON, 0644)

	return nil
}
