-module(ed25519_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs)->
    application:ensure_all_started(salt),
    ed25519_sup:start_link().

stop(_State)->
    ok.
