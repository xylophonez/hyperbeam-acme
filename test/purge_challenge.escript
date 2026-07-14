#!/usr/bin/env escript
%%% Remove ALL _acme-challenge.tunnel TXT records from permaweb.space via
%%% read-modify-write (never touches other records). Idempotent.
main(_) ->
    true = code:add_pathz("ebin"),
    St = lib_acme_dns_namecheap:new(#{
        api_user  => env("NAMECHEAP_API_USER"),
        api_key   => env("NAMECHEAP_API_KEY"),
        username  => env("NAMECHEAP_USERNAME"),
        client_ip => env("NAMECHEAP_CLIENT_IP"),
        domain    => <<"permaweb.space">>}),
    case lib_acme_dns_namecheap:clear_name(St, <<"_acme-challenge.tunnel.permaweb.space">>) of
        {ok, _} -> io:format("purged all _acme-challenge.tunnel TXT~n");
        {error, E} -> io:format("purge failed: ~p~n", [E]), halt(1)
    end.

env(N) -> case os:getenv(N) of false -> halt(2); V -> list_to_binary(V) end.
