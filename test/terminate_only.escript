#!/usr/bin/env escript
%%% Terminator-only staged proof against an ALREADY-ISSUED prod cert (no
%%% re-issue). Adds cowboy/gun paths explicitly so it doesn't depend on
%%% ERL_FLAGS. Args: lib_dir clear_port tls_port cert.pem key.pem
main([LibDir, ClearPortS, TlsPortS, CertF, KeyF]) ->
    true = code:add_pathz("ebin"),
    [code:add_pathz(filename:join([LibDir, D, "ebin"]))
     || D <- ["cowboy", "cowlib", "ranch", "gun"]],
    io:format("cowboy_router beam: ~p~n", [code:which(cowboy_router)]),
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(inets),
    ClearPort = list_to_integer(ClearPortS),
    TlsPort = list_to_integer(TlsPortS),
    {ok, Chain} = file:read_file(CertF),
    {ok, Key} = file:read_file(KeyF),

    {ok, _} = lib_acme_tls:start(#{ref => cut, tls_port => TlsPort,
                                   chain_pem => Chain, key_pem => Key,
                                   clear_host => "127.0.0.1", clear_port => ClearPort}),
    timer:sleep(500),

    ok = trust_check(TlsPort, "tunnel.permaweb.space", "apex"),
    ok = trust_check(TlsPort, "node9.tunnel.permaweb.space", "wildcard"),
    ok = proxy_check(ClearPort, TlsPort, "/~meta@1.0/info/address"),
    ok = proxy_check(ClearPort, TlsPort, "/"),
    _ = lib_acme_tls:stop(cut),
    io:format("~nSTAGED CUTOVER PROVEN: prod cert, browser-trusted TLS, faithful proxy~n").

trust_check(Port, Host, Label) ->
    Opts = [{verify, verify_peer}, {cacerts, public_key:cacerts_get()},
            {server_name_indication, Host},
            {customize_hostname_check,
             [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}],
    case ssl:connect("127.0.0.1", Port, Opts, 8000) of
        {ok, S} -> ssl:close(S),
                   io:format("ok    ~s: system-CA-trusted TLS for ~s~n", [Label, Host]);
        {error, E} -> io:format("FAIL  ~s trust: ~p~n", [Label, E]), halt(1)
    end.

proxy_check(ClearPort, TlsPort, Path) ->
    C = fetch("http", ClearPort, Path),
    T = fetch("https", TlsPort, Path),
    case {C, T} of
        {{S, B}, {S, B}} ->
            io:format("ok    proxy ~s: ~p, ~p bytes identical~n", [Path, S, byte_size(B)]);
        _ -> io:format("FAIL  proxy ~s: clear=~p tls=~p~n", [Path, C, T]), halt(1)
    end.

fetch(Scheme, Port, Path) ->
    URL = Scheme ++ "://127.0.0.1:" ++ integer_to_list(Port) ++ Path,
    Opts = [{autoredirect, false}, {ssl, [{verify, verify_none}]}, {timeout, 20000}],
    case httpc:request(get, {URL, []}, Opts, [{body_format, binary}]) of
        {ok, {{_, S, _}, _H, B}} -> {S, B};
        E -> E
    end.
