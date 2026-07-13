#!/usr/bin/env escript
%%% Offline anchor for acme_csr: generate a wildcard CSR and verify it with
%%% openssl (self-signature + subject + SANs). Requires openssl on PATH.
main(_) ->
    true = code:add_pathz("ebin"),
    Names = [<<"*.tunnel.permaweb.space">>, <<"tunnel.permaweb.space">>],
    {Der, Key} = acme_csr:generate(Names),
    ok = file:write_file("/tmp/csr_check.der", Der),
    ok = file:write_file("/tmp/csr_check_key.pem", acme_csr:key_to_pem(Key)),
    Out = os:cmd("openssl req -inform DER -in /tmp/csr_check.der -noout -verify -text 2>&1"),
    Checks = [{"self-signature", "verify OK"},
              {"apex CN", "CN=tunnel.permaweb.space"},
              {"wildcard SAN", "DNS:*.tunnel.permaweb.space"},
              {"apex SAN", "DNS:tunnel.permaweb.space"},
              {"P-256 key", "P-256"},
              {"ecdsa-sha256", "ecdsa-with-SHA256"}],
    lists:foreach(fun({What, Needle}) ->
        case string:find(Out, Needle) of
            nomatch -> io:format("FAIL  ~s (missing ~p)~n", [What, Needle]), halt(1);
            _ -> io:format("ok    ~s~n", [What])
        end
    end, Checks),
    io:format("~nCSR VERIFIED BY OPENSSL~n").
