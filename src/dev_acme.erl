%%% acme@1.0 device — on/start hook.
%%%
%%% Wires the pieces together: on node start, ensure a current wildcard cert
%%% exists (load from the store, or issue via ACME DNS-01 if missing/expiring),
%%% then bring up the in-node TLS terminator (acme_tls) that fronts the node's
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

-export([start/3]).

-define(RENEW_DAYS, 30).
-define(TLS_REF, acme_tls_listener).

%% AO-Core device hook: (Msg1, Msg2, Opts) -> {ok, Msg1}. Side effect is the
%% running terminator; the message passes through unchanged.
start(M1, _M2, Opts) ->
    Config = config(M1, Opts),
    {Chain, Key} = ensure_cert(Config),
    {ok, _} = acme_tls:start(#{
        ref => ?TLS_REF,
        tls_port => maps:get(tls_port, Config, 443),
        chain_pem => Chain,
        key_pem => Key,
        clear_host => "127.0.0.1",
        clear_port => maps:get(clear_port, Config)}),
    {ok, M1}.

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
    not acme_store:needs_renewal(Chain, {calendar:universal_time(), RenewDays}).

load_cert(ChainPath, KeyPath) ->
    case {file:read_file(ChainPath), file:read_file(KeyPath)} of
        {{ok, Chain}, {ok, Key}} -> {ok, Chain, Key};
        _ -> error
    end.

issue_and_store(Config, Dir, ChainPath, KeyPath) ->
    ok = filelib:ensure_dir(ChainPath),
    AccountKey = load_or_new_account(Dir),
    Result = acme_client:issue(#{
        directory_url => maps:get(directory_url, Config,
                                  acme_client:letsencrypt_prod()),
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
            acme_jose:account_key_from_priv(base64:decode(B64));
        _ ->
            Key = acme_jose:gen_account_key(),
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
            {acme_dns_namecheap, acme_dns_namecheap:new(Dns#{domain => Domain})};
        Other ->
            error({unsupported_dns_provider, Other})
    end.

%%% ---- config extraction --------------------------------------------------

%% Pull the device config from the message, falling back to node opts. Accepts
%% either atom or binary keys (the generic LapEE/AndEE config pattern).
config(M1, Opts) when is_map(M1) ->
    Raw = maps:merge(sub(Opts, <<"acme">>), sub(M1, <<"acme">>)),
    normalize(Raw).

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
