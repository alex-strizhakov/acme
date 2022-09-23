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
              requests: %{}
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
        {:ok, %{state | requests: Map.put(state.requests, domain, request)}}
      else
        {:ok, %{status: :ready} = request, state} ->
          send(self(), {:finalize, domain, request})
          {:ok, %{state | requests: Map.put(state.requests, domain, request)}}

        error ->
          error
      end

    {:reply, result, state}
  end

  def handle_call({:validate_token, token}, _, state) do
    IO.inspect(token, label: :token)
    IO.inspect(state, label: :state)

    {domain, request} = Enum.find(state.requests, fn {_, data} -> data.token == token end)

    {result, state} =
      if request do
        state =
          if is_nil(request.timer_ref) and request.status == :pending do
            {:ok, timer_ref} = :timer.send_interval(5_000, {:poll_status, domain})
            request = Map.put(request, :timer_ref, timer_ref)
            %{state | requests: Map.put(state.requests, domain, request)}
          else
            state
          end

        {{:ok, Enum.join([token, state.thumbprint], ".")}, state}
      else
        {{:error, :not_found}, state}
      end

    # {result, state} =
    # if Map.has_key?(state.tokens, token) do
    # tokens = List.delete(state.tokens, token)

    # state = Map.put(state, :tokens, tokens)
    # {{:ok, Enum.join([token, state.thumbprint], ".")}, state}
    # else
    # {{:error, :not_found}, state}
    # end

    {:reply, result, state}
  end

  @impl true
  def handle_info({:poll_status, requested_domain}, state) do
    {requested_domain, request} =
      Enum.find(state.requests, fn {domain, _data} -> domain == requested_domain end)

    # Enum.reduce(state.tokens, state, fn {_t, urls}, state ->
    {:ok, request, state} = poll_authorization_info(request, state)
    # state
    # end)
    state =
      if request.status == :valid do
        :timer.cancel(request.timer_ref)
        send(self(), {:finalize, requested_domain, request})
        %{state | requests: Map.put(state.requests, requested_domain, request)}
      else
        state
      end

    {:noreply, state}
  end

  def handle_info({:finalize, requested_domain, request}, state) do
    private_key = X509.PrivateKey.new_rsa(4096)

    request = Map.put(request, :private_key, private_key)

    csr =
      private_key
      |> X509.CSR.new(
        {:rdnSequence, []},
        extension_request: [X509.Certificate.Extension.subject_alt_name([requested_domain])]
      )
      |> X509.CSR.to_der()

    payload = %{"csr" => Base.url_encode64(csr, padding: false)}

    data =
      sign_jws(payload, state.private_key, %{
        "url" => request.finalize_url,
        "nonce" => state.nonce,
        "kid" => state.kid
      })

    {result, request, state} =
      with {:ok, %{headers: headers, body: body}} <-
             Tesla.post(state.client, request.finalize_url, data),
           IO.inspect(body, label: :finalize_info),
           # %{"token" => token, "url" => url} <- find_http_challenge(challenges),
           {:ok, nonce} <- get_header(headers, "replay-nonce") do
        state = %{state | nonce: nonce}

        request =
          if body["status"] == "valid" do
            # send(self(), {:finalize, finalize_url})
            # Map.put(request, :status, :valid)
            Logger.warn("we can download certificate")
            certificate_url = body["certificate"]

            payload = ""

            data =
              sign_jws(payload, state.private_key, %{
                "url" => certificate_url,
                "nonce" => state.nonce,
                "kid" => state.kid
              })

            {:ok, %{body: body}} = result = Tesla.post(state.client, certificate_url, data)
            [cert | chain] = String.split(body, ~r/^\-+END CERTIFICATE\-+$\K/m, parts: 2)

            pems = %{
              privkey: state.private_key |> JWK.to_pem() |> normalize_pem(),
              cert: normalize_pem(cert),
              chain: normalize_pem(to_string(chain))
            }

            Enum.each(
              pems,
              fn {type, content} ->
                path = Path.join(["domains", "#{type}.pem"])
                File.mkdir_p(Path.dirname(path))
                File.write!(path, content)
                File.chmod!(path, 0o600)
                # store_file!(Path.join(domain_folder(config), "#{type}.pem"), content)
              end
            )

            IO.inspect(result, label: :result_get_cert)
            request
          else
            request
          end

        {:ok, request, %{state | nonce: nonce}}
      else
        error ->
          Logger.error("fetching authorization token fail #{inspect(error)}")

          {:error, request, state}
      end

    IO.inspect(request, label: :request_after_cert)
    IO.inspect(result, label: :result_after_finalize_url)
    {:noreply, state}
    # csr = Crypto.csr(private_key, config.domains)
  end

  defp normalize_pem(pem) do
    case String.trim(pem) do
      "" -> ""
      pem -> pem <> "\n"
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

  defp get_authorization_url(request, state) do
    payload = %{identifiers: [%{type: "dns", value: request.domain}]}

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
      request = %{request | authorize_url: auth_url, finalize_url: finalize_url}

      request =
        if body["status"] == "ready" do
          Map.put(request, :status, :ready)
        else
          request
        end

      state = %{state | nonce: nonce}
      {:ok, request, state}
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

  defp get_authorization_info(request, state) do
    payload = ""

    data =
      sign_jws(payload, state.private_key, %{
        "url" => request.authorize_url,
        "nonce" => state.nonce,
        "kid" => state.kid
      })

    with {:ok, %{headers: headers, body: %{"challenges" => challenges} = body}} <-
           Tesla.post(state.client, request.authorize_url, data),
         IO.inspect(body, label: :challenges),
         %{"token" => token, "url" => url} <- find_http_challenge(challenges),
         {:ok, nonce} <- get_header(headers, "replay-nonce") do
      request = %{request | challenge_url: url, token: token}

      {
        :ok,
        request,
        %{state | nonce: nonce}
      }
    else
      error ->
        Logger.error("fetching authorization token fail #{inspect(error)}")

        {:error, state}
    end
  end

  defp poll_authorization_info(request, state) do
    payload = ""

    data =
      sign_jws(payload, state.private_key, %{
        "url" => request.authorize_url,
        "nonce" => state.nonce,
        "kid" => state.kid
      })

    with {:ok, %{headers: headers, body: body}} <-
           Tesla.post(state.client, request.authorize_url, data),
         IO.inspect(body, label: :auth_info),
         # %{"token" => token, "url" => url} <- find_http_challenge(challenges),
         {:ok, nonce} <- get_header(headers, "replay-nonce") do
      request =
        if body["status"] == "valid" do
          # send(self(), {:finalize, finalize_url})
          Map.put(request, :status, :valid)
        else
          request
        end

      {:ok, request, %{state | nonce: nonce}}
    else
      error ->
        Logger.error("fetching authorization token fail #{inspect(error)}")

        {:error, state}
    end
  end

  defp request_http_challenge(request, state) do
    payload = %{}

    data =
      sign_jws(payload, state.private_key, %{
        "url" => request.challenge_url,
        "nonce" => state.nonce,
        "kid" => state.kid
      })

    with {:ok, %{headers: headers, body: body}} <-
           Tesla.post(state.client, request.challenge_url, data),
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
