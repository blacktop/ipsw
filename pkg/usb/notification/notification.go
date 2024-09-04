package notification

import (
	"context"
	"fmt"

	"github.com/apex/log"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName         = "com.apple.mobile.notification_proxy"
	insecureServiceName = "com.apple.mobile.insecure_notification_proxy"
)

type ObserveNotificationRequest struct {
	Command string `plist:"Command,omitempty"`
	Name    string `plist:"Name,omitempty"`
}

type ObserveNotificationEvent struct {
	Command string `plist:"Command,omitempty"`
	Name    string `plist:"Name,omitempty"`
}

type Client struct {
	c *usb.Client
}

func NewClient(udid string) (*Client, error) {
	c, err := lockdownd.NewClientForService(serviceName, udid, false)
	if err != nil {
		return nil, err
	}
	return &Client{
		c: c,
	}, nil
}

func (c *Client) ObserveNotification(notification string) error {
	req := ObserveNotificationRequest{
		Command: "ObserveNotification",
		Name:    notification,
	}
	if err := c.c.Send(req); err != nil {
		return err
	}
	return nil
}

func (c *Client) ObserveAllNotifications() error {
	for _, notification := range notifications {
		req := ObserveNotificationRequest{
			Command: "ObserveNotification",
			Name:    notification,
		}
		if err := c.c.Send(req); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) PostNotification(notification string) error {
	req := ObserveNotificationEvent{
		Command: "PostNotification",
		Name:    notification,
	}
	if err := c.c.Send(req); err != nil {
		return err
	}
	return nil
}

func (c *Client) Listen(ctx context.Context) error {
	stoped := false
	event := &ObserveNotificationEvent{}

	go func() {
		<-ctx.Done()
		stoped = true
	}()

	for {
		if err := c.c.Recv(event); err != nil {
			return err
		}
		switch event.Command {
		case "RelayNotification":
			log.Info(event.Name)
		case "ProxyDeath":
			return fmt.Errorf("notification %s proxy died", event.Name)
		default:
			log.Log.Debugf("unknown notification event: %#v", event)
		}
		if stoped {
			break
		}
	}

	return nil
}

func (c *Client) shutdown() error {
	req := ObserveNotificationEvent{
		Command: "Shutdown",
	}
	if err := c.c.Send(req); err != nil {
		return err
	}
	return nil
}

func (c *Client) Close() error {
	c.shutdown()
	return c.c.Close()
}
