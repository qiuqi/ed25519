-module(ed25519_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

start_link()->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([])->
    Server = {ed25519_server,
              {ed25519_server, start_link, []},
              permanent, 5000, worker, [ed25519_server]},
    {ok, { {one_for_one, 100, 1}, [Server]}}.

