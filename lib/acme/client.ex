defmodule Acme.Client do
  defmodule Request do
    defstruct [
      :domain,
      :authorize_url,
      :finalize_url,
      :challenge_url,
      :status,
      :token,
      :timer_ref,
      :private_key
    ]
  end

  defmodule State do
    defstruct endpoints: %{},
              client: nil,
              nonce: nil,
              private_key: nil,
              kid: nil,
              thumbprint: nil,
              requests: %{},
              polling_interval: nil,
              base_path: ""
  end

  use GenServer

  require Logger

  alias JOSE.{JWK, JWS}

  def create_account(contact, server \\ __MODULE__) do
    GenServer.call(server, {:create_account, contact})
  end

  def new_cert(domain, server \\ __MODULE__) do
    GenServer.call(server, {:new_cert, domain})
  end

  def challenge(token, server \\ __MODULE__) do
    GenServer.call(server, {:validate_token, token})
  end

  def start_link(opts) do
    opts = Keyword.put_new(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: opts[:name])
  end

  @impl true
  def init(opts) do
    jwk = opts |> Keyword.fetch!(:key_path) |> JWK.from_pem_file()
    {_, jwk_map} = JWK.to_map(jwk)

    middleware = [
      {Tesla.Middleware.BaseUrl, Keyword.fetch!(opts, :base_url)},
      {Tesla.Middleware.JSON, encode_content_type: "application/jose+json"}
    ]

    state = %State{
      client: Tesla.client(middleware, opts[:adapter]),
      private_key: jwk_map,
      thumbprint: JWK.thumbprint(jwk),
      polling_interval: Keyword.get(opts, :polling_interval, 5_000),
      base_path: opts[:base_path] || ""
    }

    {:ok, state, {:continue, :initial_setup}}
  end

  @impl true
  def handle_continue(:initial_setup, state) do
    with {:ok, %{body: endpoints}} <- Tesla.get(state.client, "/directory"),
         {:ok, %{headers: headers}} <- Tesla.get(state.client, endpoints["newNonce"]) do
      state =
        state
        |> update_nonce(headers)
        |> Map.put(:endpoints, endpoints)

      {:noreply, state}
    else
      _ -> {:stop, :initial_setup_fail, nil}
    end
  end

  @impl true
  def handle_call({:create_account, contact}, _, state) do
    payload = %{termsOfServiceAgreed: true, contact: ["mailto:#{contact}"]}

    headers = %{
      "url" => state.endpoints["newAccount"],
      "nonce" => state.nonce
    }

    data = sign_jws(payload, state.private_key, headers)

    {result, state} =
      with {:ok, %{headers: headers, body: %{"status" => "valid"}}} <-
             Tesla.post(state.client, state.endpoints["newAccount"], data) do
        {:ok, kid} = get_header(headers, "location")

        state =
          state
          |> update_nonce(headers)
          |> Map.put(:kid, kid)

        {:ok, state}
      else
        error ->
          Logger.error("#{inspect(error)}")
          {:error, state}
      end

    {:reply, result, state}
  end

  def handle_call({:new_cert, domain}, _, state) do
    request = %Request{domain: domain, status: :pending}

    {result, state} =
      with {:ok, %{status: :pending} = request, state} <- get_authorization_url(request, state),
           {:ok, request, state} <- get_authorization_info(request, state),
           {:ok, state} <- request_http_challenge(request, state) do
        {:ok, put_in(state.requests[domain], request)}
      else
        {:ok, %{status: :ready} = request, state} ->
          send(self(), {:finalize, domain, request})
          {:ok, put_in(state.requests[domain], request)}

        error ->
          error
      end

    {:reply, result, state}
  end

  def handle_call({:validate_token, token}, _, state) do
    {domain, request} = Enum.find(state.requests, fn {_, data} -> data.token == token end)

    {result, state} =
      if request do
        state =
          if is_nil(request.timer_ref) and request.status == :pending do
            {:ok, timer_ref} =
              :timer.send_interval(state.polling_interval, {:poll_status, domain})

            update_in(state.requests[domain], fn request ->
              put_in(request.timer_ref, timer_ref)
            end)
          else
            state
          end

        token_check = Enum.join([token, state.thumbprint], ".")
        {{:ok, token_check}, state}
      else
        {{:error, :not_found}, state}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_info({:poll_status, domain}, state) do
    {_domain, request} = find_request_by_domain(state, domain)
    {:ok, request, state} = poll_authorization_info(request, state)

    state =
      if request.status == :valid do
        :timer.cancel(request.timer_ref)
        send(self(), {:finalize, domain})

        update_in(state.requests[domain], fn request ->
          put_in(request.timer_ref, nil)
        end)
      else
        state
      end

    {:noreply, state}
  end

  def handle_info({:finalize, domain}, state) do
    {_, request} = find_request_by_domain(state, domain)
    private_key = X509.PrivateKey.new_rsa(4096)

    csr =
      private_key
      |> X509.CSR.new(
        {:rdnSequence, []},
        extension_request: [X509.Certificate.Extension.subject_alt_name([domain])]
      )
      |> X509.CSR.to_der()

    payload = %{"csr" => Base.url_encode64(csr, padding: false)}

    data = sign_jws(payload, state.private_key, prepare_headers(state, request.finalize_url))

    state =
      with {:ok, response} <- Tesla.post(state.client, request.finalize_url, data) do
        state = update_nonce(state, response.headers)

        if response.body["status"] == "valid" do
          certificate_url = response.body["certificate"]

          data = sign_jws("", state.private_key, prepare_headers(state, certificate_url))

          {:ok, %{body: certificate} = response} = Tesla.post(state.client, certificate_url, data)

          [cert | chain] = String.split(certificate, ~r/^\-+END CERTIFICATE\-+$\K/m, parts: 2)

          priv_key = private_key |> X509.PrivateKey.to_pem() |> normalize_pem()

          %{
            privkey: normalize_pem(priv_key),
            cert: normalize_pem(cert),
            chain: normalize_pem(to_string(chain))
          }
          |> Enum.each(fn {type, content} ->
            path = Path.join([state.base_path, "domains", domain, "#{type}.pem"])
            File.mkdir_p(Path.dirname(path))
            File.write!(path, content)
            File.chmod!(path, 0o600)
          end)

          state.requests[domain]
          |> update_in(&put_in(&1.private_key, priv_key))
          |> update_nonce(response.headers)
        else
          state
        end
      else
        error ->
          Logger.error("fetching authorization token fail #{inspect(error)}")

          state
      end

    {:noreply, state}
  end

  defp get_authorization_url(request, state) do
    payload = %{identifiers: [%{type: "dns", value: request.domain}]}

    data =
      sign_jws(payload, state.private_key, prepare_headers(state, state.endpoints["newOrder"]))

    with {:ok, %{body: %{"authorizations" => [auth_url]}} = response} <-
           Tesla.post(state.client, state.endpoints["newOrder"], data) do
      request = %{request | authorize_url: auth_url, finalize_url: response.body["finalize"]}

      request =
        if response.body["status"] == "ready" do
          put_in(request.status, :ready)
        else
          request
        end

      {:ok, request, update_nonce(state, response.headers)}
    else
      error ->
        Logger.error("fetching authorization url fail #{inspect(error)}")
        {:error, state}
    end
  end

  defp get_authorization_info(request, state) do
    data = sign_jws("", state.private_key, prepare_headers(state, request.authorize_url))

    with {:ok, response} <- Tesla.post(state.client, request.authorize_url, data),
         %{"token" => token, "url" => url} <- find_http_challenge(response.body["challenges"]) do
      request = %{request | challenge_url: url, token: token}

      {:ok, request, update_nonce(state, response.headers)}
    else
      error ->
        Logger.error("fetching authorization token fail #{inspect(error)}")

        {:error, state}
    end
  end

  defp poll_authorization_info(request, state) do
    data = sign_jws("", state.private_key, prepare_headers(state, request.authorize_url))

    with {:ok, response} <- Tesla.post(state.client, request.authorize_url, data) do
      request =
        if response.body["status"] == "valid" do
          Map.put(request, :status, :valid)
        else
          request
        end

      {:ok, request, update_nonce(state, response.headers)}
    else
      error ->
        Logger.error("fetching poll authorization fail #{inspect(error)}")

        {:error, state}
    end
  end

  defp request_http_challenge(request, state) do
    data = sign_jws(%{}, state.private_key, prepare_headers(state, request.challenge_url))

    with {:ok, response} <- Tesla.post(state.client, request.challenge_url, data) do
      {:ok, update_nonce(state, response.headers)}
    else
      error ->
        Logger.error("fetching http challenge failed #{inspect(error)}")

        {:error, state}
    end
  end

  defp update_nonce(state, headers) do
    {:ok, nonce} = get_header(headers, "replay-nonce")
    Map.put(state, :nonce, nonce)
  end

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

  defp prepare_headers(state, url) do
    %{
      "nonce" => state.nonce,
      "kid" => state.kid,
      "url" => url
    }
  end

  defp find_http_challenge(challenges) do
    Enum.find(challenges, fn challenge ->
      challenge["type"] == "http-01"
    end)
  end

  def normalize_pem(pem) do
    case String.trim(pem) do
      "" -> ""
      pem -> pem <> "\n"
    end
  end

  defp find_request_by_domain(%{requests: requests}, search_domain) do
    Enum.find(requests, fn {domain, _data} -> search_domain == domain end)
  end
end
