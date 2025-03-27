package download

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"time"
)

const rssURL = "https://developer.apple.com/news/releases/rss/releases.rss"

type RssContent struct {
	Data string `xml:",chardata" json:"data,omitempty"`
}

type pubDate string

func (d pubDate) GetDate() (*time.Time, error) {
	layout := "Mon, 02 Jan 2006 15:04:05 MST"

	if location, err := time.LoadLocation("PST8PDT"); err == nil {
		t, err := time.ParseInLocation(layout, string(d), location)
		if err != nil {
			return nil, err
		}
		var tt time.Time

		zone, _ := time.Now().Zone()
		location, err = time.LoadLocation(zone)
		if err != nil {
			// return nil, fmt.Errorf("failed to load location %s: %v", zone, err)
			tt = t
		} else {
			tt = t.In(location)
		}
		return &tt, nil
	}

	tt, err := time.Parse(layout, string(d))
	if err != nil {
		return nil, fmt.Errorf("failed to parse pub date: %v", err)
	}
	return &tt, nil
}

type RssItem struct {
	Title   string     `xml:"title" json:"title,omitempty"`
	Link    string     `xml:"link" json:"link,omitempty"`
	Desc    string     `xml:"description" json:"desc,omitempty"`
	GUID    string     `xml:"guid" json:"guid,omitempty"`
	PubDate pubDate    `xml:"pubDate" json:"pub_date,omitempty"`
	Content RssContent `xml:"encoded" json:"content"`
}

type RssChannel struct {
	Title string    `xml:"title" json:"title,omitempty"`
	Link  string    `xml:"link" json:"link,omitempty"`
	Desc  string    `xml:"description" json:"desc,omitempty"`
	Items []RssItem `xml:"item" json:"items,omitempty"`
}

type Rss struct {
	Channel RssChannel `xml:"channel" json:"channel"`
}

// GetRSS returns the developer.apple.com/news/releases RSS feed as Rss object
func GetRSS() (*Rss, error) {
	resp, err := http.Get(rssURL)
	if err != nil {
		return nil, fmt.Errorf("failed to GET RSS URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RSS feed returned status: %s", resp.Status)
	}

	rss := Rss{}

	err = xml.NewDecoder(resp.Body).Decode(&rss)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSS XML: %v", err)
	}

	return &rss, nil
}
