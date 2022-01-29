package download

import (
	"encoding/xml"
	"fmt"
	"net/http"
)

const rssURL = "http://developer.apple.com/news/releases/rss/releases.rss"

type RssContent struct {
	Data string `xml:",chardata"`
}

type RssItem struct {
	Title   string     `xml:"title"`
	Link    string     `xml:"link"`
	Desc    string     `xml:"description"`
	GUID    string     `xml:"guid"`
	PubDate string     `xml:"pubDate"`
	Content RssContent `xml:"encoded"`
}

type RssChannel struct {
	Title string    `xml:"title"`
	Link  string    `xml:"link"`
	Desc  string    `xml:"description"`
	Items []RssItem `xml:"item"`
}

type Rss struct {
	Channel RssChannel `xml:"channel"`
}

// GetRSS returns the developer.apple.com/news/releases RSS feed as Rss object
func GetRSS() (*Rss, error) {
	resp, err := http.Get(rssURL)
	if err != nil {
		return nil, fmt.Errorf("failed to GET RSS URL: %v", err)
	}
	defer resp.Body.Close()

	rss := Rss{}

	err = xml.NewDecoder(resp.Body).Decode(&rss)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSS XML: %v", err)
	}

	return &rss, nil
}
