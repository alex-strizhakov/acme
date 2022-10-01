defmodule AcmeTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Mox

  alias Acme.Session
  alias Tesla.Adapter.Mock

  setup :verify_on_exit!

  @base_url "https://example.com"

  defp generate_nonce, do: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

  defp endpoints_json do
    Tesla.Mock.json(%{
      "keyChange" => @base_url <> "/acme/key-change",
      "meta" => %{
        "caaIdentities" => ["letsencrypt.org"],
        "termsOfService" =>
          "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017-w-v1.3-notice.pdf",
        "website" => "https://letsencrypt.org/docs/staging-environment/"
      },
      "newAccount" => @base_url <> "/acme/new-acct",
      "newNonce" => @base_url <> "/acme/new-nonce",
      "newOrder" => @base_url <> "/acme/new-order",
      "renewalInfo" => @base_url <> "/get/draft-aaron-ari/renewalInfo/",
      "revokeCert" => @base_url <> "/acme/revoke-cert",
      "vXA9Lrz1JjU" => @base_url <> "/t/adding-random-entries-to-the-directory/33417"
    })
  end

  def tesla_client do
    middleware = [
      {Tesla.Middleware.BaseUrl, @base_url},
      {Tesla.Middleware.JSON, encode_content_type: "application/jose+json"}
    ]

    Tesla.client(middleware, Tesla.Adapter.Mock)
  end

  describe "init/1" do
    setup do
      [directory_url: @base_url <> "/directory", new_nonce_url: @base_url <> "/acme/new-nonce"]
    end

    test "success", %{directory_url: directory_url, new_nonce_url: new_nonce_url} do
      initial_nonce = generate_nonce()

      Mock
      |> expect(:call, fn %{url: ^directory_url}, _opts ->
        {:ok, endpoints_json()}
      end)
      |> expect(:call, fn %{url: ^new_nonce_url, method: :head}, _opts ->
        {:ok, %Tesla.Env{headers: [{"replay-nonce", initial_nonce}], status: 200}}
      end)

      assert Acme.init(base_url: @base_url, adapter: Tesla.Adapter.Mock) ==
               {:ok,
                %Session{
                  account_private_key: nil,
                  authorize_url: nil,
                  certificate_url: nil,
                  challenge_url: nil,
                  client: tesla_client(),
                  domain: nil,
                  endpoints: %{
                    new_account: "https://example.com/acme/new-acct",
                    new_nonce: "https://example.com/acme/new-nonce",
                    new_order: "https://example.com/acme/new-order"
                  },
                  finalize_url: nil,
                  kid: nil,
                  nonce: initial_nonce,
                  thumbprint: nil,
                  token: nil
                }}
    end

    test "fetch endpoints error", %{directory_url: directory_url} do
      expect(Mock, :call, fn %{url: ^directory_url}, _opts ->
        {:ok, %Tesla.Env{status: 500}}
      end)

      capture_log(fn ->
        assert Acme.init(base_url: @base_url, adapter: Tesla.Adapter.Mock) ==
                 {:error, :fetch_endpoints_error}
      end) =~ "Can't fetch endpoints"
    end

    test "get new nonce error", %{directory_url: directory_url, new_nonce_url: new_nonce_url} do
      Mock
      |> expect(:call, fn %{url: ^directory_url}, _opts ->
        {:ok, endpoints_json()}
      end)
      |> expect(:call, fn %{url: ^new_nonce_url, method: :head}, _opts ->
        {:ok, %Tesla.Env{status: 500}}
      end)

      capture_log(fn ->
        assert Acme.init(base_url: @base_url, adapter: Tesla.Adapter.Mock) ==
                 {:error, :get_nonce_error}
      end) =~ "Can't get new nonce"
    end
  end

  describe "create_account/3" do
    setup do
      [new_account_url: @base_url <> "/acme/new-acct"]
    end

    test "success", %{new_account_url: new_account_url} do
      create_acc_nonce = generate_nonce()
      kid = @base_url <> "/acme/acct/66475763"

      expect(Mock, :call, fn %{
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

      session = %Session{
        endpoints: %{new_account: new_account_url},
        nonce: generate_nonce(),
        client: tesla_client()
      }

      assert {:ok,
              %Session{
                account_private_key: %JOSE.JWK{},
                thumbprint: thumbprint,
                nonce: ^create_acc_nonce,
                kid: ^kid
              }} = Acme.create_account(session, "email@example.com")

      assert is_binary(thumbprint)
    end
  end

  describe "new_order/2" do
    setup do
      [new_order_url: @base_url <> "/acme/new-order"]
    end

    test "success", %{new_order_url: new_order_url} do
      domain = "domain.com"
      new_order_nonce = generate_nonce()
      auth_url = @base_url <> "/acme/authz-v3/3484011403"
      finalize_url = @base_url <> "/acme/finalize/69004934/4274516444"

      expect(Mock, :call, fn %{
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
           body:
             Jason.encode!(%{
               "authorizations" => [auth_url],
               "finalize" => finalize_url,
               "status" => "pending"
             })
         }}
      end)

      session = %Session{
        endpoints: %{new_order: new_order_url},
        nonce: generate_nonce(),
        client: tesla_client(),
        account_private_key: JOSE.JWK.generate_key({:rsa, 4096})
      }

      assert {:ok,
              %Session{
                authorize_url: ^auth_url,
                finalize_url: ^finalize_url,
                nonce: ^new_order_nonce,
                domain: ^domain
              }} = Acme.new_order(session, domain)
    end
  end

  describe "get_http_challenge_data/1" do
    test "success" do
      auth_url = @base_url <> "/acme/authz-v3/3484011403"
      challenge_url = @base_url <> "/acme/chall-v3/3760565994/1yyChw"
      token_nonce = generate_nonce()
      token = "token"

      expect(Mock, :call, fn %{
                               url: ^auth_url,
                               headers: [{"content-type", "application/jose+json"}]
                             },
                             _ ->
        {:ok,
         %Tesla.Env{
           headers: [
             {"replay-nonce", token_nonce},
             {"content-type", "application/json"}
           ],
           body:
             Jason.encode!(%{
               "challenges" => [
                 %{"type" => "http-01", "token" => token, "url" => challenge_url}
               ]
             })
         }}
      end)

      session = %Session{
        authorize_url: auth_url,
        nonce: generate_nonce(),
        client: tesla_client(),
        account_private_key: JOSE.JWK.generate_key({:rsa, 4096})
      }

      assert {:ok, %Session{challenge_url: ^challenge_url, nonce: ^token_nonce, token: ^token}} =
               Acme.get_http_challenge_data(session)
    end
  end

  describe "request_http_challenge/1" do
    test "success" do
      challenge_url = @base_url <> "/acme/chall-v3/3760565994/1yyChw"
      challenge_nonce = generate_nonce()
      token = "token"

      expect(Mock, :call, fn %{
                               url: ^challenge_url,
                               headers: [{"content-type", "application/jose+json"}]
                             },
                             _ ->
        {:ok,
         %Tesla.Env{
           headers: [
             {"replay-nonce", challenge_nonce},
             {"content-type", "application/json"}
           ],
           body:
             Jason.encode!(%{
               "status" => "pending",
               "token" => token,
               "type" => "http-01",
               "url" => challenge_url
             })
         }}
      end)

      session = %Session{
        challenge_url: challenge_url,
        nonce: generate_nonce(),
        client: tesla_client(),
        account_private_key: JOSE.JWK.generate_key({:rsa, 4096})
      }

      assert {:ok, %Session{nonce: ^challenge_nonce}} = Acme.request_http_challenge(session)
    end
  end

  describe "get_certificate_status/1" do
    test "success" do
      auth_url = @base_url <> "/acme/authz-v3/3484011403"
      authorization_nonce = generate_nonce()

      expect(Mock, :call, fn %{
                               url: ^auth_url,
                               headers: [{"content-type", "application/jose+json"}]
                             },
                             _ ->
        {:ok,
         %Tesla.Env{
           headers: [
             {"replay-nonce", authorization_nonce},
             {"content-type", "application/json"}
           ],
           body: Jason.encode!(%{status: "valid"})
         }}
      end)

      session = %Session{
        authorize_url: auth_url,
        nonce: generate_nonce(),
        client: tesla_client(),
        account_private_key: JOSE.JWK.generate_key({:rsa, 4096})
      }

      assert {:ok, %Session{nonce: ^authorization_nonce}, :valid} =
               Acme.get_certificate_status(session)
    end
  end

  describe "upload_csr/1" do
    test "success" do
      finalize_url = @base_url <> "/acme/finalize/69004934/4274516444"
      finalize_nonce = generate_nonce()
      certificate_url = @base_url <> "/acme/cert/fabb079411e5bc4bd10e16e33d23ff5bc1b3"

      expect(Mock, :call, fn %{
                               url: ^finalize_url,
                               headers: [{"content-type", "application/jose+json"}]
                             },
                             _ ->
        {:ok,
         %Tesla.Env{
           headers: [
             {"replay-nonce", finalize_nonce},
             {"content-type", "application/json"}
           ],
           body: Jason.encode!(%{"status" => "valid", "certificate" => certificate_url})
         }}
      end)

      session = %Session{
        finalize_url: finalize_url,
        nonce: generate_nonce(),
        client: tesla_client(),
        account_private_key: JOSE.JWK.generate_key({:rsa, 4096}),
        domain: "domain.com"
      }

      assert {:ok, %Session{nonce: ^finalize_nonce, certificate_url: ^certificate_url}, :valid} =
               Acme.upload_csr(session)
    end
  end

  describe "download_certificate/1" do
    test "success" do
      certificate_url = @base_url <> "/acme/cert/fabb079411e5bc4bd10e16e33d23ff5bc1b3"
      certificate_nonce = generate_nonce()

      downloaded_cert = File.read!("test/cert.pem")

      expect(Mock, :call, fn %{
                               url: ^certificate_url,
                               headers: [{"content-type", "application/jose+json"}]
                             },
                             _ ->
        {:ok,
         %Tesla.Env{
           headers: [
             {"replay-nonce", certificate_nonce},
             {"content-type", "application/json"}
           ],
           body: Jason.encode!(downloaded_cert)
         }}
      end)

      session = %Session{
        certificate_url: certificate_url,
        nonce: generate_nonce(),
        client: tesla_client(),
        account_private_key: JOSE.JWK.generate_key({:rsa, 4096})
      }

      {:ok, %Session{nonce: ^certificate_nonce}, ^downloaded_cert} =
        Acme.download_certificate(session)
    end
  end
end
