//go:build !sandbox

package diff

// sandboxBuildTag discriminates the stub build from the sandbox-capable build in
// the sandbox cache scope. See the sandbox-tagged variant in
// sandbox_buildtag.go for the full rationale. The distinct value keeps the stub
// build's sandbox scope disjoint from a sandbox build's, so the two never share
// (and cross-hydrate) cache rows in a shared --cache-dir.
const sandboxBuildTag = "sandbox-unavailable"
