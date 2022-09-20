package static

// ExampleConfig is the config used within ipsw pipeline init.
const ExampleConfig = `# This is an example pipeline.yml file with some sensible defaults.
# Make sure to check the documentation at https://blacktop.github.io/ipsw
download:
  ipsw:
    - id: ipsw
      devices:
        - iPhone14,2
        - iPhone15,2
      latest: true
  ota:
    - id: ota
      devices:
        - iPhone14,2
        - iPhone15,2
      beta: true

extract:
  - ids:
      - ipsw
    kernelcache: true
    dyld_shared_cache: true
  - ids:
      - ota
    kernelcache: true
    dyld_shared_cache: true


# modelines, feel free to remove those if you don't want/use them:
# yaml-language-server: $schema=https://raw.githubusercontent.com/blacktop/ipsw/master/internal/pipeline/static/schema/schema.json
# vim: set ts=2 sw=2 tw=0 fo=cnqoj
`
