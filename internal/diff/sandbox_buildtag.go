//go:build sandbox

package diff

// sandboxBuildTag discriminates the sandbox-capable build from the stub build in
// the sandbox cache scope. A binary built WITH -tags sandbox produces real
// sandbox-diff rows; a binary built WITHOUT it returns ErrSandboxDiffUnavailable
// and can never produce that output. Folding this into sandboxTask.OptionsHash
// keeps the two builds on disjoint cache scopes so a stub-build run can never hit
// (and hydrate) a row a sandbox-build run wrote into a shared --cache-dir, which
// would otherwise render a sandbox section the stub build cannot itself produce.
const sandboxBuildTag = "sandbox-available"
