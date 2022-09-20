// Package middleware define middlewares for Jobs.
package middleware

import "github.com/blacktop/ipsw/internal/pipeline/context"

// Action is a function that takes a context and returns an error.
// It is is used on Pipers, Defaulters and Publishers, although they are not
// aware of this generalization.
type Action func(ctx *context.Context) error
