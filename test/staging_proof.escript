#!/usr/bin/env escript
%%% M1 proof: obtain a REAL Let's Encrypt *staging* wildcard cert for
%%% *.tunnel.permaweb.space via DNS-01, driving the live Namecheap API.
%%%
%%% Expects modules precompiled to ./ebin (erlc -o ebin src/*.erl).
%%% Reads credentials from the environment so nothing secret is committed:
%%%   NAMECHEAP_API_USER, NAMECHEAP_API_KEY, NAMECHEAP_USERNAME,
%%%   NAMECHEAP_CLIENT_IP  (must be a Namecheap-whitelisted IP)
%%% Writes staging-cert.pem and staging-key.pem on success.
main(_) ->
    true = code:add_pathz("ebin"),
    Domain = <<"permaweb.space">>,
    Identifiers = [<<"*.tunnel.permaweb.space">>, <<"tunnel.permaweb.space">>],
    Dns = acme_dns_namecheap:new(#{
        api_user  => env(<<"NAMECHEAP_API_USER">>),
        api_key   => env(<<"NAMECHEAP_API_KEY">>),
        username  => env(<<"NAMECHEAP_USERNAME">>),
        client_ip => env(<<"NAMECHEAP_CLIENT_IP">>),
        domain    => Domain}),
    io:format("Requesting LE STAGING cert for ~p~n", [Identifiers]),
    Result = acme_client:issue(#{
        directory_url => acme_client:letsencrypt_staging(),
        contact       => [<<"mailto:xylophonezygote@gmail.com">>],
        identifiers   => Identifiers,
        dns_settle    => 60000,
        dns           => {acme_dns_namecheap, Dns}}),
    case Result of
        {ok, #{certificate := Chain, certificate_key := KeyPem}} ->
            ok = file:write_file("staging-cert.pem", Chain),
            ok = file:write_file("staging-key.pem", KeyPem),
            io:format("~nISSUED. wrote staging-cert.pem (~p bytes) + staging-key.pem~n",
                      [byte_size(Chain)]);
        {error, Reason} ->
            io:format("~nFAILED: ~p~n", [Reason]),
            halt(1)
    end.

env(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> io:format("missing env ~s~n", [Name]), halt(2);
        V -> list_to_binary(V)
    end.
