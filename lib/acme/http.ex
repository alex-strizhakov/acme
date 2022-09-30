defmodule Acme.HTTP do
  @moduledoc """
  Module to make HTTP requests.
  """

  require Logger

  alias Acme.Session
  alias JOSE.JWK
  alias JOSE.JWS

  @spec init_client(keyword) :: Tesla.Client.t()
  def init_client(opts \\ []) do
    base_url = Keyword.get(opts, :base_url, "https://acme-v02.api.letsencrypt.org")

    middleware = [
      {Tesla.Middleware.BaseUrl, base_url},
      {Tesla.Middleware.JSON, encode_content_type: "application/jose+json"}
    ]

    adapter = Keyword.get(opts, :adapter, Tesla.Adapter.Hackney)
    Tesla.client(middleware, adapter)
  end

  @spec fetch_endpoints(Tesla.Client.t()) :: {:ok, map} | {:error, any}
  def fetch_endpoints(client) do
    with {:ok, %{body: directory_urls, status: 200}} <- Tesla.get(client, "/directory") do
      endpoints =
        directory_urls
        |> Map.take(~w(newNonce newOrder newAccount))
        |> Map.new(fn {k, url} ->
          key = k |> Macro.underscore() |> String.to_atom()
          {key, url}
        end)

      {:ok, endpoints}
    else
      error ->
        Logger.error("Can't fetch endpoints #{inspect(error)}")
        {:error, :fetch_endpoints_error}
    end
  end

  @spec get_new_nonce(Tesla.Client.t(), Path.t()) :: {:ok, String.t()} | {:error, any}
  def get_new_nonce(client, path) do
    with {:ok, %{headers: headers, status: 200}} <- Tesla.head(client, path) do
      get_nonce(headers)
    else
      error ->
        Logger.error("Can't get new nonce #{inspect(error)}")
        {:error, :get_nonce_error}
    end
  end

  @spec create_account(Session.t(), String.t(), keyword) ::
          {:ok, String.t(), String.t(), String.t(), String.t()} | {:error, any}
  def create_account(session, email, opts \\ []) do
    terms_agreed = Keyword.get(opts, :terms_agreed, true)
    return_existing = Keyword.get(opts, :return_existing, false)

    account_private_key =
      Keyword.get(opts, :account_private_key, JOSE.JWK.generate_key({:rsa, 4096}))

    payload = %{
      termsOfServiceAgreed: terms_agreed,
      onlyReturnExisting: return_existing,
      contact: ["mailto:#{email}"]
    }

    url = session.endpoints[:new_account]
    headers = %{"url" => url, "nonce" => session.nonce}

    data = sign_jws(payload, account_private_key, headers)

    with {:ok, %{headers: headers, body: %{"status" => "valid"}}} <-
           Tesla.post(session.client, url, data),
         {:ok, nonce} <- get_nonce(headers),
         {:ok, kid} <- get_header(headers, "location") do
      {:ok, nonce, kid, account_private_key, JWK.thumbprint(account_private_key)}
    else
      error ->
        Logger.error("Can't create account #{inspect(error)}")
        {:error, :create_account_error}
    end
  end

  @spec new_order(Session.t(), String.t()) ::
          {:ok, String.t(), String.t(), String.t()} | {:error, any}
  def new_order(session, domain) do
    payload = %{identifiers: [%{type: "dns", value: domain}]}

    url = session.endpoints[:new_order]
    data = sign_jws(payload, session.account_private_key, prepare_headers(session, url))

    with {:ok, %{headers: headers, body: body}} <- Tesla.post(session.client, url, data),
         {:ok, nonce} <- get_nonce(headers) do
      [authorize_url] = body["authorizations"]

      {:ok, nonce, authorize_url, body["finalize"]}
    else
      error ->
        Logger.error("Can't create new order #{inspect(error)}")
        {:error, :new_order_error}
    end
  end

  @spec get_http_challenge_data(Session.t()) ::
          {:ok, String.t(), String.t(), String.t()} | {:error, any}
  def get_http_challenge_data(session) do
    url = session.authorize_url
    data = sign_jws("", session.account_private_key, prepare_headers(session, url))

    with {:ok, %{headers: headers, body: body}} <- Tesla.post(session.client, url, data),
         {:ok, nonce} <- get_nonce(headers) do
      %{"url" => challenge_url, "token" => token} =
        Enum.find(body["challenges"], fn challenge ->
          challenge["type"] == "http-01"
        end)

      {:ok, nonce, challenge_url, token}
    else
      error ->
        Logger.error("Can't get HTTP challenge data #{inspect(error)}")
        {:error, :get_http_challenge_data_error}
    end
  end

  @spec request_http_challenge(Session.t()) :: {:ok, String.t()} | {:error, any}
  def request_http_challenge(session) do
    url = session.challenge_url
    data = sign_jws(%{}, session.account_private_key, prepare_headers(session, url))

    with {:ok, %{headers: headers}} <- Tesla.post(session.client, url, data) do
      get_nonce(headers)
    else
      error ->
        Logger.error("Can't request HTTP challenge #{inspect(error)}")
        {:error, :request_http_challenge_error}
    end
  end

  @spec get_certificate_status(Session.t()) ::
          {:ok, String.t(), :valid | :not_valid} | {:error, any}
  def get_certificate_status(session) do
    url = session.authorize_url
    data = sign_jws("", session.account_private_key, prepare_headers(session, url))

    with {:ok, %{headers: headers, body: body}} <- Tesla.post(session.client, url, data),
         {:ok, nonce} <- get_nonce(headers) do
      status = if body["status"] == "valid", do: :valid, else: :not_valid
      {:ok, nonce, status}
    else
      error ->
        Logger.error("Can't get HTTP challenge data #{inspect(error)}")
        {:error, :get_http_challenge_data_error}
    end
  end

  @spec upload_csr(Session.t()) ::
          {:ok, String.t(), :valid | :not_valid, String.t()} | {:error, any}
  def upload_csr(session) do
    url = session.finalize_url
    private_key = X509.PrivateKey.new_rsa(4096)

    csr =
      private_key
      |> X509.CSR.new(
        {:rdnSequence, []},
        extension_request: [X509.Certificate.Extension.subject_alt_name([session.domain])]
      )
      |> X509.CSR.to_der()

    payload = %{"csr" => Base.url_encode64(csr, padding: false)}

    data = sign_jws(payload, session.account_private_key, prepare_headers(session, url))

    with {:ok, %{headers: headers, body: body}} <- Tesla.post(session.client, url, data),
         {:ok, nonce} <- get_nonce(headers) do
      status = if body["status"] == "valid", do: :valid, else: :not_valid
      {:ok, nonce, status, body["certificate"]}
    else
      error ->
        Logger.error("Can't upload CSR #{inspect(error)}")
        {:error, :upload_csr_error}
    end
  end

  @spec download_certificate(Session.t()) :: {:ok, String.t(), String.t()} | {:error, any}
  def download_certificate(session) do
    url = session.certificate_url
    data = sign_jws("", session.account_private_key, prepare_headers(session, url))

    with {:ok, %{headers: headers, body: certificate}} <- Tesla.post(session.client, url, data),
         {:ok, nonce} <- get_nonce(headers) do
      {:ok, nonce, certificate}
    else
      error ->
        Logger.error("Can't download certificate #{inspect(error)}")
        {:error, :download_certificate_error}
    end
  end

  defp prepare_headers(session, url) do
    %{
      "nonce" => session.nonce,
      "kid" => session.kid,
      "url" => url
    }
  end

  defp get_nonce(headers), do: get_header(headers, "replay-nonce")

  defp get_header(headers, header) do
    case List.keyfind(headers, header, 0) do
      {^header, value} -> {:ok, value}
      _ -> {:error, :header_not_found}
    end
  end

  defp sign_jws(payload, private_key, extra_protected_header) do
    {_, jwk} = JWK.to_public_map(private_key)

    protected = Map.put(extra_protected_header, "alg", jwk_to_alg(jwk))

    protected =
      if Map.has_key?(protected, "kid") do
        protected
      else
        Map.put(protected, "jwk", jwk)
      end

    payload =
      if payload == "" do
        payload
      else
        Jason.encode!(payload)
      end

    {_, jwk} = JWS.sign(private_key, payload, protected)
    jwk
  end

  defp jwk_to_alg(%{"kty" => "RSA"}), do: "RS256"
  defp jwk_to_alg(%{"kty" => "EC", "crv" => "P-256"}), do: "ES256"
  defp jwk_to_alg(%{"kty" => "EC", "crv" => "P-384"}), do: "ES384"
  defp jwk_to_alg(%{"kty" => "EC", "crv" => "P-521"}), do: "ES512"
end
