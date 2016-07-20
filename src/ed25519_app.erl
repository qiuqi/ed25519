-module(ed25519_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs)->
    ed25519_sup:start_link().

stop(_State)->
    ok.