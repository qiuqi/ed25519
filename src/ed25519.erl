-module('ed25519').

%% API exports
-export([decrypt/4]).
-export([getkey/0]).
-export([getkeyhex/0]).
-export([encrypt/2]).
-export([newkey/0]).
-export([setkey/4]).
-export([sign/1]).
-export([status/0]).

%%====================================================================
%% API functions
%%====================================================================

%% @doc
%% return: {ok, ServerPubBin}
-spec getkey()->{ok, binary()}.
getkey()->
    {ok, ServerPubBin, _ServerSecBin} = ed25519_server:getkey(),
    {ok, ServerPubBin}.


%% @doc
%% return: {ok, ServerPubHex}
-spec getkeyhex()->{ok, list()}.
getkeyhex()->
    {ok, ServerPubHex, _ServerSecHex} = ed25519_server:getkeyhex(),
    {ok, ServerPubHex}.

-spec decrypt(binary(), binary(), binary(), binary())->{ok, binary()}.
decrypt(PeerPub, Nonce, MsgKey, MsgCipher)->
    {ok, _ServerPubBin, ServerSecBin} = ed25519_server:getkey(),
    {ok, MsgKeyPlain} = salt:crypto_box_open(MsgKey, Nonce, PeerPub, ServerSecBin),
    salt:crypto_secretbox_open(MsgCipher, Nonce, MsgKeyPlain).

-spec encrypt(binary(), binary())->{ok, list(), binary(), binary()}.
encrypt(PeerPub, Message)->
    {ok, _ServerPubBin, ServerSecBin} = ed25519_server:getkey(),
    MsgKeyClear = getSecretBoxKey(),
    Nonce = getNonce(),
    NonceBin = list_to_binary(Nonce),
    MsgKeyCipher = salt:crypto_box(MsgKeyClear, NonceBin, PeerPub, ServerSecBin),
    MsgCipher = salt:crypto_secretbox(Message, NonceBin, MsgKeyClear),
    {ok, Nonce, MsgKeyCipher, MsgCipher}.

%% @doc
%% {ok, BoxPubHex, BoxSecHex, SignPubHex, SignSecHex}
-spec newkey()->{ok, list(), list(), list(), list()}.
newkey()->
    ed25519_server:newkey().

-spec setkey(list(), list(), list(), list())->ok.
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
getNonce()->
    {M, S, I} = erlang:timestamp(),
    lists:flatten(io_lib:format("~24.10.0B", [trunc(M*1000000000+S*1000+I/1000)])).

getSecretBoxKey()->
    sha2:hexdigest256(salt:crypto_random_bytes(32)).

