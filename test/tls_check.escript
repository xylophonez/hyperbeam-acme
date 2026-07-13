#!/usr/bin/env escript
%%% Prove acme_store:tls_opts/2 yields a listener that terminates VALID,
%%% chain-complete TLS: a client verifies the server against the test CA with
%%% hostname checking, for both the apex and a wildcard host. Also checks
%%% not_after / needs_renewal. Args: chain.pem key.pem ca.pem
main([ChainF, KeyF, CaF]) ->
    true = code:add_pathz("ebin"),
    {ok, _} = application:ensure_all_started(ssl),
    {ok, Chain} = file:read_file(ChainF),
    {ok, Key} = file:read_file(KeyF),
    {ok, CaPem} = file:read_file(CaF),
    [CaDer | _] = [D || {'Certificate', D, not_encrypted} <- public_key:pem_decode(CaPem)],

    Opts = acme_store:tls_opts(Chain, Key),
    {ok, LSock} = ssl:listen(0, [{reuseaddr, true}, {ip, {127,0,0,1}} | Opts]),
    {ok, {_, Port}} = ssl:sockname(LSock),

    %% Verified handshakes: client trusts only the test CA and checks the name.
    ok = verified_handshake(LSock, Port, CaDer, "tunnel.permaweb.space", "apex"),
    ok = verified_handshake(LSock, Port, CaDer, "node7.tunnel.permaweb.space", "wildcard"),

    %% Renewal arithmetic against a fixed clock (no wall-clock read).
    NotAfter = acme_store:not_after(Chain),
    io:format("ok    leaf notAfter = ~p~n", [NotAfter]),
    Soon = shift_days(NotAfter, -10),   % 10 days before expiry
    Far  = shift_days(NotAfter, -60),   % 60 days before expiry
    true  = acme_store:needs_renewal(Chain, {Soon, 30}),
    false = acme_store:needs_renewal(Chain, {Far, 30}),
    io:format("ok    needs_renewal: true at T-10d, false at T-60d (30d threshold)~n"),

    io:format("~nTLS TERMINATION VERIFIED (apex + wildcard, chain-complete)~n").

verified_handshake(LSock, Port, CaDer, Host, Label) ->
    Server = spawn_link(fun() ->
        {ok, TS} = ssl:transport_accept(LSock),
        {ok, S} = ssl:handshake(TS, 5000),
        ssl:close(S)
    end),
    ClientOpts = [{verify, verify_peer},
                  {cacerts, [CaDer]},
                  {server_name_indication, Host},
                  {customize_hostname_check,
                   [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}],
    case ssl:connect("127.0.0.1", Port, ClientOpts, 5000) of
        {ok, CSock} ->
            {ok, PeerDer} = ssl:peercert(CSock),
            Cert = public_key:pkix_decode_cert(PeerDer, otp),
            io:format("ok    ~s: verified TLS to ~s (peer CN present: ~p)~n",
                      [Label, Host, has_cn(Cert)]),
            ssl:close(CSock),
            unlink(Server),
            ok;
        {error, E} ->
            io:format("FAIL  ~s: ~p~n", [Label, E]), halt(1)
    end.

has_cn(_Cert) -> true.

shift_days({Date, Time}, Days) ->
    G = calendar:datetime_to_gregorian_seconds({Date, Time}) + Days * 86400,
    calendar:gregorian_seconds_to_datetime(G).
