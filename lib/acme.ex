defmodule Acme do
  @moduledoc """
  Documentation for `Acme`.
  """

  alias Acme.Client

  defdelegate create_account(account), to: Client
  defdelegate new_cert(domain), to: Client
end
