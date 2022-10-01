# Acme

Wrapper library to work with Letsencrypt API V2. Functionality is quite limited, e.g. certificate renewal is not implemented and support only HTTP challenge.
Implemented:
- account creation
- new order for certificate creation
- HTTP challenge fetching
- request HTTP challenge
- certificate status fetching
- CSR uploading
- certificate download


## Installation

```elixir
def deps do
  [
    {:acme, github: "alex-strizhakov/acme"}
  ]
end
```

## Usage

```elixir
# for testing you can change `base_url` to `https://acme-staging-v02.api.letsencrypt.org`
{:ok, session} = Acme.init()
{:ok, session} = Acme.create_account(session, "email@example.com")
{:ok, session} = Acme.new_order(session, "example.com")
# token will be needed when Letsencrypt will make requests for HTTP challenge to `http://example.com/.well-known/acme-challenge/#{token}`
{:ok, %{token: token} = session} = Acme.get_http_challenge_data(session)
{:ok, session} = Acme.request_http_challenge(session)
# after successful challenge you can check certificate challenge status
{:ok, session, challenge_status} = Acme.get_certificate_status(session)
# if `challenge_status` is `:valid` you can upload CSR
{:ok, session, certificate_status} = Acme.upload_csr(session)
# if `certificate_status` is valid you can download certificate
{:ok, session, certificate} = Acme.download_certificate(session)
```

## Copyright and License

Copyright (c) 2022, Alexander Strizhakov.

Acme source code is licensed under the [MIT License](LICENSE.md).
