#!/usr/bin/env escript
%%% Staged prod cutover proof (does NOT touch 443/Caddy):
%%%  1. issue a REAL Let's Encrypt production wildcard cert via DNS-01,
%%%  2. bring up lib_acme_tls on a spare port in front of the live broker,
%%%  3. prove a client verifies the terminator against the SYSTEM CA store
%%%     (browser-trusted) for apex + wildcard, and
%%%  4. prove the proxy still relays the real broker byte-for-byte.
%%% Writes prod-cert.pem/prod-key.pem for the final flip. Args: clear_port tls_port
-include_lib("public_key/include/public_key.hrl").

main([ClearPortS, TlsPortS]) ->
    true = code:add_pathz("ebin"),
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(inets),
    ClearPort = list_to_integer(ClearPortS),
    TlsPort = list_to_integer(TlsPortS),

    Dns = lib_acme_dns_namecheap:new(#{
        api_user => env("NAMECHEAP_API_USER"), api_key => env("NAMECHEAP_API_KEY"),
        username => env("NAMECHEAP_USERNAME"), client_ip => env("NAMECHEAP_CLIENT_IP"),
        domain => <<"permaweb.space">>}),
    io:format("issuing PRODUCTION cert for *.tunnel.permaweb.space ...~n"),
    {ok, #{certificate := Chain, certificate_key := Key}} =
        lib_acme_client:issue(#{
            directory_url => lib_acme_client:letsencrypt_prod(),
            contact => [<<"mailto:xylophonezygote@gmail.com">>],
            identifiers => [<<"*.tunnel.permaweb.space">>, <<"tunnel.permaweb.space">>],
            dns_settle => 60000,
            dns => {lib_acme_dns_namecheap, Dns}}),
    ok = file:write_file("prod-cert.pem", Chain),
    ok = file:write_file("prod-key.pem", Key),
    io:format("issued: chain ~p bytes, issuer=~s~n", [byte_size(Chain), issuer(Chain)]),

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

%% Verify the terminator against the SYSTEM CA store (what a browser does).
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

issuer(ChainPem) ->
    [Der | _] = [D || {'Certificate', D, not_encrypted} <- public_key:pem_decode(ChainPem)],
    C = public_key:pkix_decode_cert(Der, otp),
    {rdnSequence, Rdn} = (C#'OTPCertificate'.tbsCertificate)#'OTPTBSCertificate'.issuer,
    case [V || ATVs <- Rdn, #'AttributeTypeAndValue'{type = {2,5,4,10}, value = V} <- ATVs] of
        [Org | _] -> io_lib:format("~p", [Org]);
        _ -> "?"
    end.

env(N) -> case os:getenv(N) of false -> halt(2); V -> list_to_binary(V) end.
