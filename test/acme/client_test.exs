defmodule Acme.ClientTest do
  use ExUnit.Case, async: true
  use Plug.Test

  import Mox

  alias Acme.Client
  alias Tesla.Adapter.Mock

  setup :verify_on_exit!

  test "register certificate" do
    base_url = "https://example.com"
    endpoints = endpoints(base_url)

    %{"newNonce" => new_nonce_url, "newAccount" => new_account_url, "newOrder" => new_order_url} =
      endpoints

    directory_url = base_url <> "/directory"
    auth_url = base_url <> "/acme/authz-v3/3484011403"
    kid = base_url <> "/acme/acct/66475763"
    token = "some_token"

    initial_nonce = generate_nonce()
    create_acc_nonce = generate_nonce()
    token_cert_nonce = generate_nonce()
    new_order_nonce = generate_nonce()

    Mock
    |> expect(:call, fn %{url: ^directory_url}, _opts ->
      {:ok, Tesla.Mock.json(endpoints)}
    end)
    |> expect(:call, fn %{url: ^new_nonce_url}, _ ->
      {:ok, %Tesla.Env{headers: [{"replay-nonce", initial_nonce}]}}
    end)
    |> expect(:call, fn %{
                          url: ^new_account_url,
                          headers: [{"content-type", "application/jose+json"}]
                        },
                        _ ->
      {:ok,
       %Tesla.Env{
         headers: [
           {"replay-nonce", create_acc_nonce},
           {"location", kid},
           {"content-type", "application/json"}
         ],
         body: Jason.encode!(%{"status" => "valid"})
       }}
    end)
    |> expect(:call, fn %{
                          url: ^new_order_url,
                          headers: [{"content-type", "application/jose+json"}]
                        },
                        _ ->
      {:ok,
       %Tesla.Env{
         headers: [
           {"replay-nonce", new_order_nonce},
           {"content-type", "application/json"}
         ],
         body: Jason.encode!(%{"authorizations" => [auth_url]})
       }}
    end)
    |> expect(:call, fn %{
                          url: ^auth_url,
                          headers: [{"content-type", "application/jose+json"}]
                        },
                        _ ->
      {:ok,
       %Tesla.Env{
         headers: [
           {"replay-nonce", token_cert_nonce},
           {"content-type", "application/json"}
         ],
         body: Jason.encode!(%{"challenges" => [%{"type" => "http-01", "token" => token}]})
       }}
    end)

    opts = [
      name: Acme.ClientTest,
      base_url: base_url,
      adapter: Tesla.Adapter.Mock,
      key_path: "test/selfsigned_key.pem"
    ]

    {:ok, pid} = start_supervised({Client, opts}, restart: :temporary)
    allow(Mock, self(), pid)

    assert is_pid(pid)
    assert Process.alive?(pid)
    state = :sys.get_state(pid)

    assert state == %Acme.Client.State{
             client: %Tesla.Client{
               adapter: {Tesla.Adapter.Mock, :call, [[]]},
               fun: nil,
               post: [],
               pre: [
                 {Tesla.Middleware.BaseUrl, :call, [base_url]},
                 {Tesla.Middleware.JSON, :call, [[encode_content_type: "application/jose+json"]]}
               ]
             },
             endpoints: endpoints,
             kid: nil,
             nonce: initial_nonce,
             private_key: %{
               "e" => "AQAB",
               "kty" => "RSA",
               "n" =>
                 "v2M-nOs6hz5kQttweIVXX1QeYdc3QHRmlyJnC0mnwUdPNrvOTMMTvRJEQquD9D3jYjCPJMcQZCT3V51ComschQsTvNHQjqxqnAYozvnrhFzUTeanifSPec4V_DRaHPu8I_ha5umSusmgMOjxNSOiSB7Scz8fizHDMPiHyCPVz3LEoC1vi4hTJj9j0u_CuEenTDuEyS9beXH7pWZaRQfGe0-_R53orfKzOdO29nXS5gXYtdOvxWex-QCfYlf6iYPqo1R4DOvNpvKoZIPnNF028a60mWhmCXSPlQmgro1LHa-rZoPRmEGPWM2g2OZpAQDlAHsMy7dFCTGo_Ch-MhQEew",
               "d" =>
                 "J68Xa4gm4aYhOe-wWX0kicKybg0nCrlYEFx0y1VhcGUt2qaEd0w3youAFebkfH9cp55z_-c60dkMZGFaUL0u87NBS3Sh7wN3M5TfX1NY72AkMWbzNFq-aT4_NsVQLhRQhZDYoGqsHwjxq1KRuTgDTTr-3iCnlMAjvgK6fNhZXCMO9lQGeXGT-0I1roLH2zqD09MisykHzSBfjPjvaqb5yQOR0XI-dE0cUeIbO027tjQZYg9OqbDPZeUbKpAi5UvoYOCt7w5ynzqhxbp-XhlOcGzzION-MwpnAYwcgrbcQrw-Ct7cj4sIlBx2grugVV-_bp6JO1ws4LzklEHe-90-uQ",
               "dp" =>
                 "M8naqSmPIQ_N015QoIkLOO612BefLWBiyUD7fOOq1qKkKw5TIPKvoH_fa3MIRClEqPVL1t83aQtQUEw5ijIitwFP-GYCKOvS7dKDq1mWONLnYmylWJYe6pnwoEPNoykNXeK4jUWss4wjq3wiGwk_hjNIIbLS8tCMCIdg9z1of2E",
               "dq" =>
                 "k6iT_QN6MggQubROB3lCMTpcNHFdV4wVXJJFz-gKcQmtIIxhYrOnlFVpcrLwVI8c1PiZqQuuSeL-5NiChoqv_4Mjf-J2M1fiCv66fK8DsATPFVnk6nAJdJHFVXuC4kx0xJCis2O1d-7UmXta245mQZrj8k2onz9XAUVAcUT-5rk",
               "p" =>
                 "7Yveg19TCgO08r5sV5vf7YtNPLrBTtPa57NBnDjmYki43RIHJ2Dn-fiLhsfg4aPZVsEEhKQ7xrbHclIqQZImATgGxHqZWfrD-KTdRi-dtsZh2fHONmMJeSKaIHk5vwt59ffNQjCgaoO2dhsw3PFIO2ROWezgR7stdQYwtbjmba8",
               "q" =>
                 "zkFolazRxXR8Xsr-6x7FmR5VhuDJ45zwmxazToxqQGKj8SrBY5sBQUCO3n1FoYPjFPiVNPHSIbokNRNumDdiehYJxbyzvcWEBq7JAgbrr6-A24Y6JPou1yZTIOgBTC16lmJRq6LxCWtUMV5dFDpe6xYxoyRds3VbKCCSnUfytPU",
               "qi" =>
                 "Gi84WHNOcf3nQUJw6ibRlNz_fn3UMzXNTrtFuZXGaXMS3HGz6_jA17surJjWCB2TW0lNCCtjLgC5u4KSzINT9F_8uogLl1H7ns_S8DBJrUnk2545H_k0dsTiaS0SmmSD0X8AQNPxq44arC09_Xi5aI3LwnV4d4Ji-AZgqJQTGC8"
             },
             thumbprint: "Y0elpL8gynwnjT7xJlDBmdap7obVA_EFNh-TOzBg6l4",
             tokens: []
           }

    assert :ok = Client.create_account("email@example.com", pid)
    state = :sys.get_state(pid)
    assert state.nonce == create_acc_nonce
    assert state.kid == kid

    assert :ok = Client.new_cert("domain.com", pid)
    state = :sys.get_state(pid)
    assert state.nonce == token_cert_nonce
    assert state.tokens == [token]

    conn =
      :get
      |> conn("/.well-known/acme-challenge/" <> token)
      |> Acme.ChallengePlug.call(pid)

    assert conn.state == :sent
    assert conn.status == 200
    assert conn.resp_body == Enum.join([token, state.thumbprint], ".")
  end

  defp endpoints(base_url) do
    %{
      "keyChange" => "#{base_url}/acme/key-change",
      "meta" => %{
        "caaIdentities" => ["letsencrypt.org"],
        "termsOfService" =>
          "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017-w-v1.3-notice.pdf",
        "website" => "https://letsencrypt.org/docs/staging-environment/"
      },
      "newAccount" => "#{base_url}/acme/new-acct",
      "newNonce" => "#{base_url}/acme/new-nonce",
      "newOrder" => "#{base_url}/acme/new-order",
      "renewalInfo" => "#{base_url}/get/draft-aaron-ari/renewalInfo/",
      "revokeCert" => "#{base_url}/acme/revoke-cert",
      "vXA9Lrz1JjU" => "#{base_url}/t/adding-random-entries-to-the-directory/33417"
    }
  end

  defp generate_nonce, do: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
end
