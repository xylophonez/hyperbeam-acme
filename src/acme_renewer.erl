%%% Periodic certificate renewal for acme@1.0.
%%%
%%% A tiny gen_server that, on an interval, reads the on-disk chain and — if it
%%% is within `renew_days` of expiry — runs the injected `renew_fun` (which
%%% re-issues, stores, and hot-swaps the terminator's cert). The clock and the
%%% renew action are parameters, so the decision logic is testable without a CA,
%%% a node, or wall-clock waits.
-module(acme_renewer).
-behaviour(gen_server).

-export([start_link/1, check_now/1, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% Opts:
%%   chain_path  :: file path of the current cert-chain PEM
%%   renew_days  :: renew when fewer than this many days remain (default 30)
%%   interval_ms :: how often to check (default 12h)
%%   renew_fun   :: fun(() -> ok | {error, term()})
%%   clock_fun   :: fun(() -> calendar:datetime())  (default universal_time)
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

%% Force an immediate check (used by tests and by an operator poke).
check_now(Pid) -> gen_server:call(Pid, check_now, 60000).

stop(Pid) -> gen_server:stop(Pid).

%%% ---- gen_server ---------------------------------------------------------

init(Opts) ->
    State = #{chain_path => maps:get(chain_path, Opts),
              renew_days => maps:get(renew_days, Opts, 30),
              interval => maps:get(interval_ms, Opts, 12 * 60 * 60 * 1000),
              renew_fun => maps:get(renew_fun, Opts),
              clock_fun => maps:get(clock_fun, Opts, fun calendar:universal_time/0)},
    {ok, schedule(State)}.

handle_call(check_now, _From, State) ->
    {reply, do_check(State), State};
handle_call(_, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_, State) -> {noreply, State}.

handle_info(check, State) ->
    _ = do_check(State),
    {noreply, schedule(State)};
handle_info(_, State) ->
    {noreply, State}.

terminate(_Reason, _State) -> ok.

%%% ---- internals ----------------------------------------------------------

schedule(#{interval := Interval} = State) ->
    erlang:send_after(Interval, self(), check),
    State.

%% Returns {renewed, Result} | not_due | {error, Reason}.
do_check(#{chain_path := Path, renew_days := Days,
           renew_fun := RenewFun, clock_fun := Clock}) ->
    case file:read_file(Path) of
        {ok, Chain} ->
            case acme_store:needs_renewal(Chain, {Clock(), Days}) of
                true -> {renewed, RenewFun()};
                false -> not_due
            end;
        {error, R} ->
            %% No cert yet -> treat as due so first boot issues.
            {renewed, RenewFun(), {no_chain, R}}
    end.
