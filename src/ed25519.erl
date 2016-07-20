-module('ed25519').

%% API exports
-export([decrypt/4]).

%%====================================================================
%% API functions
%%====================================================================

decrypt(PeerPubHex, Nonce, MsgKey64, MsgCipher64)->
    PeerPubBin = hex:hexstr_to_bin(PeerPubHex),
    MsgKeyBin = base64:decode(MsgKey64),
    {ok, _ServerPubBin, ServerSecBin} = ed25519_server:getkey(),
    {ok, MsgKey} = salt:crypto_box_open(MsgKeyBin, Nonce, PeerPubBin, ServerSecBin),
    MsgBin = base64:decode(MsgCipher64),
    {ok, Msg} = salt:crypto_secretbox_open(MsgBin, Nonce, MsgKey),
    {ok, Msg}.


%%====================================================================
%% Internal functions
%%====================================================================
