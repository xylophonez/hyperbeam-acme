%%% acme@1.0 device — on/start hook.
%%%
%%% Wires the pieces together: on node start, ensure a current wildcard cert
%%% exists (load from the store, or issue via ACME DNS-01 if missing/expiring),
%%% then bring up the in-node TLS terminator (lib_acme_tls) that fronts the node's
%%% cleartext listener. The result: a LapEE that is its own tunnel provider edge,
%%% terminating public TLS with no companion box and no base change.
%%%
%%% Config (under the device's message / node opts), all optional but `domain`
%%% and the DNS credentials are required to issue:
%%%   domain        e.g. <<"permaweb.space">>
%%%   identifiers   [<<"*.tunnel.permaweb.space">>, <<"tunnel.permaweb.space">>]
%%%   tls-port      default 443
%%%   clear-port    the node's own cleartext port (defaults from node opts)
%%%   cert-dir      where cert/key/account persist (encrypted store root)
%%%   directory-url ACME directory (defaults to Let's Encrypt production)
%%%   renew-days    renew when fewer than N days remain (default 30)
%%%   dns           #{provider => <<"namecheap">>, api_user, api_key,
%%%                   username, client_ip}
-module(dev_acme).

-export([info/1, run/3]).

%% Shared library modules bundled into the acme@1.0 device archive by the forge
%% packager (hb_packager scans these lib_* modules and rewrites inter-module
%% calls under the device's hashed root).
-device_libraries([lib_acme_jose,
                   lib_acme_csr,
                   lib_acme_client,
                   lib_acme_dns_namecheap,
                   lib_acme_store,
                   lib_acme_tls,
                   lib_acme_tls_proxy,
                   lib_acme_renewer]).

-define(RENEW_DAYS, 30).
-define(TLS_REF, acme_tls_listener).

%% Declare the device's callable keys so HyperBEAM can dispatch the on/start
%% hook to start/3 (without this, dispatch raises function_clause).
info(_) ->
    #{ exports => [<<"run">>] }.

%% AO-Core device hook: (Msg1, Msg2, Opts) -> {ok, Msg1}. Side effects are the
%% running terminator and renewer; the message passes through unchanged.
run(M1, _M2, Opts) ->
    io:format("ACME_RUN_ENTERED~n"),
    %% Never crash the node boot: run the whole bring-up in a spawned process
    %% and log any failure, so a provider issue degrades to "no TLS" rather than
    %% a boot loop. The hook returns immediately.
    _ = spawn(fun() -> bringup(config(M1, Opts)) end),
    {ok, M1}.

bringup(Config) ->
    try
        ok = publish_a_records(Config),
        {Chain, Key} = ensure_cert(Config),
        ok = start_terminator(Config, Chain, Key),
        {ok, _} = lib_acme_renewer:start_link(#{
            chain_path => chain_path(Config),
            renew_days => maps:get(renew_days, Config, ?RENEW_DAYS),
            interval_ms => maps:get(renew_interval_ms, Config, 12 * 60 * 60 * 1000),
            renew_fun => fun() -> renew(Config) end}),
        io:format("ACME_PROVIDER_UP tls-port=~p~n", [maps:get(tls_port, Config, 443)])
    catch
        Class:Reason:Stack ->
            io:format("ACME_PROVIDER_FAIL ~p:~p~n  config-keys=~p~n  ~p~n",
                      [Class, Reason, maps:keys(Config), Stack])
    end.

start_terminator(Config, Chain, Key) ->
    _ = lib_acme_tls:stop(?TLS_REF),
    {ok, _} = lib_acme_tls:start(#{
        ref => ?TLS_REF,
        tls_port => maps:get(tls_port, Config, 443),
        chain_pem => Chain,
        key_pem => Key,
        clear_host => "127.0.0.1",
        clear_port => maps:get(clear_port, Config)}),
    ok.

%% Re-issue and hot-swap the live cert (called by the renewer).
renew(Config) ->
    Dir = maps:get(cert_dir, Config),
    {Chain, Key} = issue_and_store(Config, Dir, chain_path(Config), key_path(Config)),
    start_terminator(Config, Chain, Key).

%% Publish the node's own A records so DNS points the wildcard + apex at it.
%% Optional: only runs when a public IP is known and the provider supports it.
publish_a_records(Config) ->
    case public_ip(Config) of
        undefined -> ok;
        Ip ->
            {Mod, State} = dns_provider(Config),
            case erlang:function_exported(Mod, ensure_a, 3) of
                true ->
                    lists:foldl(
                      fun(Id, S) ->
                              {ok, S1} = Mod:ensure_a(S, a_name(Id, Config), Ip),
                              S1
                      end, State, maps:get(identifiers, Config)),
                    ok;
                false -> ok
            end
    end.

%% A record host for an identifier: the name itself (wildcard included), under
%% the managed domain.
a_name(Id, _Config) -> Id.

public_ip(Config) ->
    case maps:get(public_ip, Config, undefined) of
        undefined -> maps:get(client_ip, maps:get(dns, Config, #{}), undefined);
        Ip -> Ip
    end.

chain_path(Config) -> filename:join(maps:get(cert_dir, Config), "cert-chain.pem").
key_path(Config) -> filename:join(maps:get(cert_dir, Config), "cert-key.pem").

%%% ---- certificate lifecycle ----------------------------------------------

ensure_cert(Config) ->
    Dir = maps:get(cert_dir, Config),
    ChainPath = filename:join(Dir, "cert-chain.pem"),
    KeyPath = filename:join(Dir, "cert-key.pem"),
    case load_cert(ChainPath, KeyPath) of
        {ok, Chain, Key} ->
            case fresh_enough(Chain, Config) of
                true -> {Chain, Key};
                false -> issue_and_store(Config, Dir, ChainPath, KeyPath)
            end;
        error ->
            issue_and_store(Config, Dir, ChainPath, KeyPath)
    end.

fresh_enough(Chain, Config) ->
    RenewDays = maps:get(renew_days, Config, ?RENEW_DAYS),
    not lib_acme_store:needs_renewal(Chain, {calendar:universal_time(), RenewDays}).

load_cert(ChainPath, KeyPath) ->
    case {file:read_file(ChainPath), file:read_file(KeyPath)} of
        {{ok, Chain}, {ok, Key}} -> {ok, Chain, Key};
        _ -> error
    end.

issue_and_store(Config, Dir, ChainPath, KeyPath) ->
    ok = filelib:ensure_dir(ChainPath),
    AccountKey = load_or_new_account(Dir),
    Result = lib_acme_client:issue(#{
        directory_url => maps:get(directory_url, Config,
                                  lib_acme_client:letsencrypt_prod()),
        account_key => AccountKey,
        contact => maps:get(contact, Config, []),
        identifiers => maps:get(identifiers, Config),
        dns => dns_provider(Config)}),
    case Result of
        {ok, #{certificate := Chain, certificate_key := Key}} ->
            ok = file:write_file(ChainPath, Chain),
            ok = write_private(KeyPath, Key),
            {Chain, Key};
        {error, Reason} ->
            error({acme_issue_failed, Reason})
    end.

%% Persist/reuse the ACME account key across renewals so we don't register a new
%% account each time. Stored as the raw private scalar, base64-encoded.
load_or_new_account(Dir) ->
    Path = filename:join(Dir, "account.key"),
    case file:read_file(Path) of
        {ok, B64} ->
            lib_acme_jose:account_key_from_priv(base64:decode(B64));
        _ ->
            Key = lib_acme_jose:gen_account_key(),
            #{d := Priv} = Key,
            ok = filelib:ensure_dir(Path),
            ok = write_private(Path, base64:encode(Priv)),
            Key
    end.

write_private(Path, Bytes) ->
    ok = file:write_file(Path, Bytes),
    _ = file:change_mode(Path, 8#600),
    ok.

%%% ---- DNS provider selection ---------------------------------------------

%% `domain' lives at the config top level; the provider needs it, so fold it
%% into the dns submap here.
dns_provider(#{dns := Dns, domain := Domain}) ->
    case maps:get(provider, Dns, undefined) of
        <<"namecheap">> ->
            {lib_acme_dns_namecheap, lib_acme_dns_namecheap:new(Dns#{domain => Domain})};
        Other ->
            error({unsupported_dns_provider, Other})
    end.

%%% ---- config extraction --------------------------------------------------

%% Pull the device config from the message, falling back to node opts. Accepts
%% either atom or binary keys (the generic LapEE/AndEE config pattern).
%% The acme block lives at the node-config top level (Opts). M1 (the hook Base)
%% may not be a map, so never guard on it.
config(M1, Opts) ->
    FromMsg = case is_map(M1) of true -> sub(M1, <<"acme">>); false -> #{} end,
    normalize(maps:merge(sub(Opts, <<"acme">>), FromMsg)).

sub(Map, Key) when is_map(Map) ->
    case maps:get(Key, Map, maps:get(binary_to_atom(Key, utf8), Map, #{})) of
        M when is_map(M) -> M;
        _ -> #{}
    end;
sub(_, _) -> #{}.

normalize(Map) ->
    maps:fold(fun(K, V, Acc) -> Acc#{norm_key(K) => norm_val(V)} end, #{}, Map).

norm_key(K) when is_binary(K) ->
    binary_to_atom(binary:replace(K, <<"-">>, <<"_">>, [global]), utf8);
norm_key(K) -> K.

norm_val(V) when is_map(V) -> normalize(V);
norm_val(V) -> V.
