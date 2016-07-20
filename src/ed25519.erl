-module('ed25519').

%% API exports
-export([decrypt/4]).
-export([status/0]).

%%====================================================================
%% API functions
%%====================================================================

-spec decrypt(binary(), binary(), binary(), binary())->{ok, binary()}.
decrypt(PeerPub, Nonce, MsgKey, MsgCipher)->
    {ok, _ServerPubBin, ServerSecBin} = ed25519_server:getkey(),
    {ok, MsgKey} = salt:crypto_box_open(MsgKey, Nonce, PeerPub, ServerSecBin),
    {ok, Msg} = salt:crypto_secretbox_open(MsgCipher, Nonce, MsgKey),
    {ok, Msg}.


status()->
    ed25519_server:status().


%%====================================================================
%% Internal functions
%%====================================================================
