-module('ed25519').

%% API exports
-export([decrypt/4]).
-export([setkey/4]).
-export([sign/1]).
-export([status/0]).

%%====================================================================
%% API functions
%%====================================================================

-spec decrypt(binary(), binary(), binary(), binary())->{ok, binary()}.
decrypt(PeerPub, Nonce, MsgKey, MsgCipher)->
    {ok, _ServerPubBin, ServerSecBin} = ed25519_server:getkey(),
    {ok, MsgKeyPlain} = salt:crypto_box_open(MsgKey, Nonce, PeerPub, ServerSecBin),
    salt:crypto_secretbox_open(MsgCipher, Nonce, MsgKeyPlain).

setkey(BoxPub, SignPub, BoxSec, SignSec)->
    ed25519_server:setkey(BoxPub, SignPub, BoxSec, SignSec).

-spec sign(list())->binary().
sign(Message)->
    ed25519_server:sign(Message).


status()->
    ed25519_server:status().


%%====================================================================
%% Internal functions
%%====================================================================
