defmodule Acme do
  @moduledoc """
  Documentation for `Acme`.
  """

  require Logger

  alias Acme.HTTP

  defmodule Session do
    defstruct [
      :endpoints,
      :client,
      :nonce,
      :kid,
      :account_private_key,
      :thumbprint,
      :domain,
      :authorize_url,
      :finalize_url,
      :challenge_url,
      :token,
      :certificate_url,
      :private_key
    ]

    @type t :: %__MODULE__{
            endpoints: %{new_nonce: Path.t(), new_order: Path.t(), new_account: Path.t()},
            client: Tesla.Client.t(),
            nonce: String.t(),
            kid: String.t(),
            account_private_key: map,
            thumbprint: String.t(),
            domain: String.t(),
            authorize_url: String.t(),
            finalize_url: String.t(),
            challenge_url: String.t(),
            token: String.t(),
            certificate_url: String.t(),
            private_key: String.t()
          }
  end

  @doc """
  Initializes session.
  Options:
    * base_url - base url for ACME endpoints (default: `https://acme-v02.api.letsencrypt.org`)
    * adapter - adapter for Tesla.Client (default : `Tesla.Adapter.Hackney`)
  """
  @spec init(keyword) :: {:ok, Session.t()} | {:error, any}
  def init(opts \\ []) do
    client = HTTP.init_client(opts)

    with {:ok, endpoints} <- HTTP.fetch_endpoints(client),
         {:ok, nonce} <- HTTP.get_new_nonce(client, endpoints[:new_nonce]) do
      {:ok, %Session{endpoints: endpoints, client: client, nonce: nonce}}
    end
  end

  @doc """
  Creates new account.
  Options:
    * terms_agreed - indicates that client is agreed with terms of service, by default `true`
    * return_existing - don't create new account, check for existing, by default `false`
    * account_private_key - private key from the account, by default will be generated
  """
  @spec create_account(Session.t(), String.t(), keyword) :: {:ok, Session.t()} | {:error, any}
  def create_account(session, email, opts \\ []) do
    with {:ok, nonce, kid, account_private_key, thumbprint} <-
           HTTP.create_account(session, email, opts) do
      {:ok,
       Map.merge(session, %{
         account_private_key: account_private_key,
         thumbprint: thumbprint,
         nonce: nonce,
         kid: kid
       })}
    end
  end

  @doc """
  Creates order for new certificate for the domain.
  """
  @spec new_order(Session.t(), String.t()) :: {:ok, Session.t()} | {:error, any}
  def new_order(session, domain) do
    with {:ok, nonce, authorize_url, finalize_url} <- HTTP.new_order(session, domain) do
      {:ok,
       Map.merge(session, %{
         authorize_url: authorize_url,
         finalize_url: finalize_url,
         nonce: nonce,
         domain: domain
       })}
    end
  end

  @doc """
  Loads data for HTTP challenge.
  """
  @spec get_http_challenge_data(Session.t()) :: {:ok, Session.t()} | {:error, any}
  def get_http_challenge_data(%{authorize_url: url} = session) when is_binary(url) do
    with {:ok, nonce, challenge_url, token} <- HTTP.get_http_challenge_data(session) do
      {:ok, Map.merge(session, %{challenge_url: challenge_url, token: token, nonce: nonce})}
    end
  end

  @doc """
  Requests HTTP challenge. Should be called when everything is ready for challenge.
  """
  @spec request_http_challenge(Session.t()) :: {:ok, Session.t()} | {:error, any}
  def request_http_challenge(%{challenge_url: url} = session) when is_binary(url) do
    with {:ok, nonce} <- HTTP.request_http_challenge(session) do
      {:ok, Map.put(session, :nonce, nonce)}
    end
  end

  @doc """
  Gets certificate status.
  """
  @spec get_certificate_status(Session.t()) ::
          {:ok, Session.t(), :valid | :not_valid} | {:error, any}
  def get_certificate_status(session) do
    with {:ok, nonce, status} <- HTTP.get_certificate_status(session) do
      {:ok, Map.put(session, :nonce, nonce), status}
    end
  end

  @doc """
  Upload CSR for the certificate.
  """
  @spec upload_csr(Session.t()) :: {:ok, Session.t(), :valid | :not_valid} | {:error, any}
  def upload_csr(%{finalize_url: url} = session) when is_binary(url) do
    with {:ok, nonce, status, private_key, certificate_url} <- HTTP.upload_csr(session) do
      {:ok,
       Map.merge(session, %{
         nonce: nonce,
         certificate_url: certificate_url,
         private_key: private_key
       }), status}
    end
  end

  @doc """
  Downloads certificate.
  """
  @spec download_certificate(Session.t()) :: {:ok, Session.t(), String.t()} | {:error, any}
  def download_certificate(%{certificate_url: url} = session) when is_binary(url) do
    with {:ok, nonce, certificate} <- HTTP.download_certificate(session) do
      {:ok, Map.put(session, :nonce, nonce), certificate}
    end
  end
end
