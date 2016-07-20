-module(ed25519_server).
-behaviour(gen_server).

-export([start_link/0]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-export([getkey/0]).
-export([setkey/4]).
-export([sign/1]).
-export([status/0]).

-record(state, {boxpub, signpub, boxsec, signsec}).

start_link()->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

getkey()->
    gen_server:call(?MODULE, {getkey}).

setkey(BoxPub, SignPub, BoxSec, SignSec)->
    gen_server:call(?MODULE, {setkey, BoxPub, SignPub, BoxSec, SignSec}).


sign(Message)->
    gen_server:call(?MODULE, {sign, Message}).

status()->
    gen_server:call(?MODULE, {status}).

%% ---------------------------------------
%% gen_server callbacks
%% ---------------------------------------

init(_)->
    process_flag(trap_exit, true),
    {ok, #state{}}.

handle_call({getkey}, _From, State)->
    {reply, {ok, State#state.boxpub, State#state.boxsec}, State};
handle_call({setkey, BoxPub, SignPub, BoxSec, SignSec}, _From, _State)->
    {reply, ok, #state{
                   boxpub = hex:hexstr_to_bin(BoxPub),
                   signpub = hex:hexstr_to_bin(SignPub),
                   boxsec = hex:hexstr_to_bin(BoxSec),
                   signsec = hex:hexstr_to_bin(SignSec)}};
handle_call({sign, Message}, _From, State)->
    {reply, salt:crypto_sign(Message, State#state.signsec), State};
handle_call({status}, _From, State)->
    {reply, {ok, State#state.boxpub}, State}.


handle_cast(_Msg, State)->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

