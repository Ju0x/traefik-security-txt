# traefik-security-txt
Traefik middleware plugin serving a security.txt ([RFC9116](https://datatracker.ietf.org/doc/html/rfc9116))

### Generate a security.txt

To get all fields for the configuration you can generate a security.txt here:
> https://securitytxt.org/

## Setup

Add this plugin to your static configuration (e.g. `traefik.yml`)

```yml
# ... contents of traefik.yml

experimental:
  plugins:
    security-txt:
      moduleName: github.com/Ju0x/traefik-security-txt
      version: v0.1.0
```


## Example of a simple configuration

```yml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - security-txt-plugin

  services:
   service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1
  
  middlewares:
    security-txt-plugin:
      plugin:
        security-txt:
            Contact: "mailto:test@example.test"
            Expires: "2026-12-31T23:59:00.000Z"
            PreferredLanguages: "en, de, dk"
```


## Example of a more complex configuration

```yml
# ... contents of dynamic.yml

middlewares:
  security-txt-plugin:
    plugin:
      security-txt:
        Contact:
            - "mailto:test@example.test"
            - "https://example.test/contact"
        Expires: "2026-12-31T23:59:00.000Z"
        Encryption: "https://example.test/pgp-key.txt"
        Acknowledgements: "https://example.test/hall-of-fame.html"
        PreferredLanguages: "en, de, dk"
        Policy:
            - "https://example.test/security-policy.html"
            - "https://bughunter.example.test/security-policy.html"
        Hiring: "https://example.test/jobs.html"
        CSAF: 
            - "https://example.test/.well-known/csaf/provider-metadata.json"
            - "https://example.test/csaf/provider-metadata.json"
```

## TODO

    - Add the Canonical field and make it possible to sign the contents of the security.txt