#!/usr/bin/env escript
%%% Offline anchor for lib_acme_renewer: with an injected clock, it renews when the
%%% cert is within the threshold, holds otherwise, and treats a missing chain as
%%% due (first-boot issuance). No CA, no node, no waiting. Args: chain.pem
main([ChainF]) ->
    true = code:add_pathz("ebin"),
    {ok, Chain} = file:read_file(ChainF),
    NotAfter = lib_acme_store:not_after(Chain),
    Soon = shift_days(NotAfter, -10),   % within 30d threshold
    Far  = shift_days(NotAfter, -60),   % outside it

    {renewed, did_renew} = run(ChainF, Soon),
    io:format("ok    renews when within threshold~n"),

    not_due = run(ChainF, Far),
    io:format("ok    holds when far from expiry~n"),

    {renewed, did_renew, {no_chain, _}} = run("/nonexistent/none.pem", Far),
    io:format("ok    missing chain -> issues on first boot~n"),

    io:format("~nRENEWER LOGIC VERIFIED~n").

run(ChainPath, Now) ->
    {ok, Pid} = lib_acme_renewer:start_link(#{
        chain_path => ChainPath, renew_days => 30, interval_ms => 3600000,
        renew_fun => fun() -> did_renew end,
        clock_fun => fun() -> Now end}),
    R = lib_acme_renewer:check_now(Pid),
    lib_acme_renewer:stop(Pid),
    R.

shift_days({Date, Time}, Days) ->
    G = calendar:datetime_to_gregorian_seconds({Date, Time}) + Days * 86400,
    calendar:gregorian_seconds_to_datetime(G).
