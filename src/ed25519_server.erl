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

-record(state, {boxpub, signpub, boxsec, signsec}).

start_link()->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

getkey()->
    gen_server:call(?MODULE, {getkey}).

%% ---------------------------------------
%% gen_server callbacks
%% ---------------------------------------

init(_)->
    process_flag(trap_exit, true),
    {ok, #state{
            boxpub = hex:hexstr_to_bin("7038130a3af6bbcd8228d988862863991a22c39eb704b11fb6b1314d9792ec59"),
            signpub = hex:hexstr_to_bin("dce48481808df3b6a37d14c83c4d326519edae3086d92f1d48cafbe1852a45ee"),
            boxsec = hex:hexstr_to_bin("4317252e7e248223c26f0b3210f4faeaa4626c83f41bed1e9182692c368fb064"),
            signsec = hex:hexstr_to_bin("96e1679639279e898263b2c4bbe829cb34c8fd5f9923e04bae6b1d99fb64d49ddce48481808df3b6a37d14c83c4d326519edae3086d92f1d48cafbe1852a45ee")
           }
    }.

handle_call({getkey}, _From, State)->
    {reply, {ok, State#state.boxpub, State#state.boxsec}, State}.


handle_cast(_Msg, State)->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

