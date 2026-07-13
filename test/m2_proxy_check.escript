#!/usr/bin/env escript
%%% M2 in-node proof: stand up the acme_tls terminator (cowboy:start_tls) in
%%% front of a REAL running HyperBEAM cleartext listener, and prove every
%%% response relays byte-for-byte (status + Location + body) through TLS.
%%%
%%% Run with cowboy/gun/ranch/cowlib on the path (via ERL_FLAGS -pa) and the
%%% acme_* beams in ./ebin. Args: cert.pem key.pem clear_port tls_port
main([CertF, KeyF, ClearPortS, TlsPortS]) ->
    true = code:add_pathz("ebin"),
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(inets),
    ClearPort = list_to_integer(ClearPortS),
    TlsPort = list_to_integer(TlsPortS),
    {ok, Chain} = file:read_file(CertF),
    {ok, Key} = file:read_file(KeyF),

    {ok, _} = acme_tls:start(#{ref => m2test, tls_port => TlsPort,
                               chain_pem => Chain, key_pem => Key,
                               clear_host => "127.0.0.1", clear_port => ClearPort}),
    timer:sleep(300),

    Paths = ["/~meta@1.0/info", "/~meta@1.0/info/address", "/",
             "/~hyperbuddy@1.0/index", "/does-not-exist-xyz"],
    Results = [compare(P, ClearPort, TlsPort) || P <- Paths],
    _ = acme_tls:stop(m2test),

    Fails = [R || R = {_, fail, _} <- Results],
    lists:foreach(fun({P, Verdict, Info}) ->
        io:format("~-8s ~-26s ~s~n", [Verdict, P, Info])
    end, Results),
    case Fails of
        [] -> io:format("~nM2 PROXY FAITHFUL: all paths byte-identical through TLS~n");
        _  -> io:format("~n~p PATH(S) DIFFERED~n", [length(Fails)]), halt(1)
    end.

compare(Path, ClearPort, TlsPort) ->
    Clear = fetch("http", ClearPort, Path),
    Tls   = fetch("https", TlsPort, Path),
    case {Clear, Tls} of
        {{S, L, B}, {S, L, B}} ->
            {Path, ok, io_lib:format("~p, ~p bytes, loc=~p", [S, byte_size(B), L])};
        {{Sc, Lc, Bc}, {St, Lt, Bt}} ->
            {Path, fail,
             io_lib:format("clear=~p/~pB/~p  tls=~p/~pB/~p",
                           [Sc, byte_size(Bc), Lc, St, byte_size(Bt), Lt])};
        {C, T} ->
            {Path, fail, io_lib:format("clear=~p tls=~p", [C, T])}
    end.

fetch(Scheme, Port, Path) ->
    URL = Scheme ++ "://127.0.0.1:" ++ integer_to_list(Port) ++ Path,
    HTTPOpts = [{autoredirect, false}, {timeout, 20000},
                {ssl, [{verify, verify_none}]}],
    case httpc:request(get, {URL, []}, HTTPOpts, [{body_format, binary}]) of
        {ok, {{_, S, _}, H, B}} -> {S, location(H), B};
        {error, E} -> {error, E}
    end.

location(Headers) ->
    case lists:keyfind("location", 1, [{string:lowercase(K), V} || {K, V} <- Headers]) of
        {_, V} -> list_to_binary(V);
        false -> undefined
    end.
