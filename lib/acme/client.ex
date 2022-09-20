defmodule Acme.Client do
  defmodule State do
    defstruct endpoints: %{},
              client: nil,
              nonce: nil,
              private_key: nil,
              kid: nil,
              thumbprint: nil,
              tokens: %{}
  end

  use GenServer

  require Logger

  alias JOSE.{JWK, JWS}

  def start_link(opts) do
    opts = Keyword.put_new(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: opts[:name])
  end

  @impl true
  def init(opts) do
    jwk = opts |> Keyword.fetch!(:key_path) |> JWK.from_pem_file()
    {_, jwk_map} = jwk |> JWK.to_map()

    middleware = [
      {Tesla.Middleware.BaseUrl, Keyword.fetch!(opts, :base_url)},
      {Tesla.Middleware.JSON, encode_content_type: "application/jose+json"}
    ]

    state = %State{
      client: Tesla.client(middleware, opts[:adapter]),
      private_key: jwk_map,
      thumbprint: JWK.thumbprint(jwk)
    }

    {:ok, state, {:continue, :initial_setup}}
  end

  def create_account(contact, server \\ __MODULE__) do
    GenServer.call(server, {:create_account, contact})
  end

  def new_cert(domain, server \\ __MODULE__) do
    GenServer.call(server, {:new_cert, domain})
  end

  def challenge(token, server \\ __MODULE__) do
    GenServer.call(server, {:validate_token, token})
  end

  defp get_header(headers, header) do
    case List.keyfind(headers, header, 0) do
      {^header, value} -> {:ok, value}
      _ -> {:error, :header_not_found}
    end
  end

  @impl true
  def handle_continue(:initial_setup, state) do
    with {:ok, %{body: endpoints}} <- Tesla.get(state.client, "/directory"),
         {:ok, %{headers: headers}} <- Tesla.get(state.client, endpoints["newNonce"]),
         {:ok, nonce} <- get_header(headers, "replay-nonce") do
      state = %{state | endpoints: endpoints, nonce: nonce}
      {:noreply, state}
    else
      _ -> {:stop, :initial_setup_fail, nil}
    end
  end

  @impl true
  def handle_call({:create_account, contact}, _, state) do
    payload = %{termsOfServiceAgreed: true, contact: ["mailto:#{contact}"]}

    data =
      sign_jws(payload, state.private_key, %{
        "url" => state.endpoints["newAccount"],
        "nonce" => state.nonce
      })

    {result, state} =
      with {:ok, %{headers: headers, body: %{"status" => "valid"}}} <-
             Tesla.post(state.client, state.endpoints["newAccount"], data),
           {:ok, nonce} <- get_header(headers, "replay-nonce"),
           {:ok, kid} <- get_header(headers, "location") do
        state = %{state | nonce: nonce, kid: kid}
        {:ok, state}
      else
        _ ->
          {:error, state}
      end

    {:reply, result, state}
  end

  def handle_call({:new_cert, domain}, _, state) do
    {result, state} =
      with {:ok, auth_url, finalize_url, state} <- get_authorization_url(domain, state),
           {:ok, challenge_url, state} <- get_authorization_info(auth_url, finalize_url, state),
           {:ok, state} <- request_http_challenge(challenge_url, state) do
        {:ok, timer_ref} = :timer.send_interval(5_000, :poll_status)
        {:ok, Map.put(state, :timer_ref, timer_ref)}
      end

    {:reply, result, state}
  end

  def handle_call({:validate_token, token}, _, state) do
    IO.inspect(token, label: :token)
    IO.inspect(state, label: :state)

    {result, state} =
      if Map.has_key?(state.tokens, token) do
        # tokens = List.delete(state.tokens, token)

        # state = Map.put(state, :tokens, tokens)
        {{:ok, Enum.join([token, state.thumbprint], ".")}, state}
      else
        {{:error, :not_found}, state}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_info(:poll_status, state) do
    state =
      Enum.reduce(state.tokens, state, fn {_t, urls}, state ->
        {:ok, state} = poll_authorization_info(urls[:auth_url], state)
        state
      end)

    {:noreply, state}
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

  defp get_authorization_url(domain, state) do
    payload = %{identifiers: [%{type: "dns", value: domain}]}

    data =
      sign_jws(payload, state.private_key, %{
        "url" => state.endpoints["newOrder"],
        "nonce" => state.nonce,
        "kid" => state.kid
      })

    with {:ok,
          %{
            headers: headers,
            body: %{"authorizations" => [auth_url], "finalize" => finalize_url} = body
          }} <-
           Tesla.post(state.client, state.endpoints["newOrder"], data),
         IO.inspect(body, label: "body"),
         {:ok, nonce} <- get_header(headers, "replay-nonce") do
      state = Map.put(state, :nonce, nonce)
      {:ok, auth_url, finalize_url, state}
    else
      error ->
        Logger.error("fetching authorization url fail #{inspect(error)}")
        {:error, state}
    end
  end

  defp find_http_challenge(challenges) do
    Enum.find(challenges, fn challenge ->
      challenge["type"] == "http-01"
    end)
  end

  defp get_authorization_info(auth_url, finalize_url, state) do
    payload = ""

    data =
      sign_jws(payload, state.private_key, %{
        "url" => auth_url,
        "nonce" => state.nonce,
        "kid" => state.kid
      })

    with {:ok, %{headers: headers, body: %{"challenges" => challenges} = body}} <-
           Tesla.post(state.client, auth_url, data),
         IO.inspect(body, label: :challenges),
         %{"token" => token, "url" => url} <- find_http_challenge(challenges),
         {:ok, nonce} <- get_header(headers, "replay-nonce") do
      {:ok, url,
       %{
         state
         | nonce: nonce,
           tokens: Map.put(state.tokens, token, %{auth_url: auth_url, finalize_url: finalize_url})
       }}
    else
      error ->
        Logger.error("fetching authorization token fail #{inspect(error)}")

        {:error, state}
    end
  end

  defp poll_authorization_info(auth_url, state) do
    payload = ""

    data =
      sign_jws(payload, state.private_key, %{
        "url" => auth_url,
        "nonce" => state.nonce,
        "kid" => state.kid
      })

    with {:ok, %{headers: headers, body: body}} <- Tesla.post(state.client, auth_url, data),
         IO.inspect(body, label: :auth_info),
         # %{"token" => token, "url" => url} <- find_http_challenge(challenges),
         {:ok, nonce} <- get_header(headers, "replay-nonce") do
      {:ok, %{state | nonce: nonce}}
    else
      error ->
        Logger.error("fetching authorization token fail #{inspect(error)}")

        {:error, state}
    end
  end

  defp request_http_challenge(challenge_url, state) do
    payload = %{}

    data =
      sign_jws(payload, state.private_key, %{
        "url" => challenge_url,
        "nonce" => state.nonce,
        "kid" => state.kid
      })

    with {:ok, %{headers: headers, body: body}} <-
           Tesla.post(state.client, challenge_url, data),
         IO.inspect(body, label: :after_challenge_request),
         # %{"token" => token, "url" => url} <- find_http_challenge(challenges),
         {:ok, nonce} <- get_header(headers, "replay-nonce") do
      {:ok, %{state | nonce: nonce}}
    else
      error ->
        Logger.error("fetching authorization token fail #{inspect(error)}")

        {:error, state}
    end
  end
end
