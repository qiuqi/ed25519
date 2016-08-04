-module(libws).
-include_lib("liberl/include/liberl.hrl").
-export([decrypt/4]).
-export([encrypt/2]).
-export([encrypt_json/2]).
-export([decode/2]).

decrypt(PeerPubHex, Nonce, MsgKey64, Msg64)->
    ed25519:decrypt(?HTOB(PeerPubHex), ?BIN(Nonce), base64:decode(MsgKey64), base64:decode(Msg64)).


encrypt(PeerPubHex, Message)->
    {ok, Nonce, Key, Msg} =  ed25519:encrypt(?HTOB(PeerPubHex), ?BIN(Message)),
    Json = [
            {"t", ?U("m")},
            {"n", ?U(Nonce)},
            {"k", ?U(base64:encode(Key))},
            {"m", ?U(base64:encode(Msg))}
           ],
    mochijson2:encode(Json).

encrypt_json(PeerPub, Json)->
    Msg = mochijson2:encode(Json),
    encrypt(PeerPub, Msg).

decode(PeerPub, MsgCipher)->
    {struct, Json} = ?JSON_DECODE(MsgCipher),
    Nonce = ?GETVALUE(<<"n">>, Json),
    Key = ?GETVALUE(<<"k">>, Json),
    Msg = ?GETVALUE(<<"m">>, Json),
    case decrypt(PeerPub, Nonce, Key, Msg) of 
        {ok, Plain} ->
            ?JSON_DECODE(Plain);
        _ ->
            {sturct, null}
    end.



