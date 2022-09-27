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
    case conn.request_path do
      "/.well-known/acme-challenge/" <> token ->
        case Acme.Client.challenge(token, client) do
          {:ok, authorization} ->
            conn |> send_resp(200, authorization) |> halt()

          {:error, _} ->
            conn |> send_resp(404, "Not found") |> halt()
        end

      _ ->
        conn
    end
  end
end
