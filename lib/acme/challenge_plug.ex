defmodule Acme.ChallengePlug do
  @behaviour Plug
  import Plug.Conn

  require Logger

  @impl true
  def init(opts) do
    Keyword.get(opts, :acme_client, Acme.Client)
  end

  @impl true
  def call(conn, client) do
    Logger.warn("request for #{conn.request_path}")

    case conn.request_path do
      "/.well-known/acme-challenge/" <> token ->
        Logger.warn("started challenge for #{token}")

        case Acme.Client.challenge(token, client) do
          {:ok, authorization} ->
            Logger.warn("challenge success")
            conn |> send_resp(200, authorization) |> halt()

          {:error, _} = error ->
            Logger.error("challenge error #{inspect(error)}")
            conn |> send_resp(404, "Not found") |> halt()
        end

      _ ->
        conn
    end
  end
end
