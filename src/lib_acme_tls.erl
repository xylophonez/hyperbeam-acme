%%% In-node TLS terminator for the acme@1.0 device (M2, device-only path).
%%%
%%% Opens a second cowboy listener that terminates public TLS with the stored
%%% ACME certificate and reverse-proxies every request to the node's local
%%% cleartext listener. This internalises the companion box (Caddy): the TLS key
%%% never leaves the appliance, and no base change to hb_http_server is needed.
%%%
%%% Runs inside HyperBEAM, so it uses the cowboy/gun already on the node. It is
%%% NOT compiled or run by the offline test suite; lib_acme_store carries the part
%%% that is provable without a node.
-module(lib_acme_tls).

-export([start/1, stop/1]).

%% Config:
%%   #{ref, tls_port, chain_pem, key_pem, clear_host, clear_port}
-spec start(map()) -> {ok, pid()} | {error, term()}.
start(#{ref := Ref, tls_port := Port, chain_pem := Chain, key_pem := Key,
        clear_host := CHost, clear_port := CPort}) ->
    _ = application:ensure_all_started(cowboy),
    _ = application:ensure_all_started(gun),
    TlsOpts = lib_acme_store:tls_opts(Chain, Key),
    Dispatch = cowboy_router:compile(
        [{'_', [{'_', lib_acme_tls_proxy, #{clear_host => CHost, clear_port => CPort}}]}]),
    cowboy:start_tls(
        Ref,
        #{socket_opts => [{port, Port} | TlsOpts],
          max_connections => infinity},
        #{env => #{dispatch => Dispatch}}).

-spec stop(term()) -> ok | {error, not_found}.
stop(Ref) ->
    cowboy:stop_listener(Ref).
