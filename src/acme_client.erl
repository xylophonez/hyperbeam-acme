%%% ACME (RFC 8555) client: DNS-01 order -> issued certificate chain.
%%%
%%% Dependency-free beyond OTP (inets/ssl/crypto/public_key/json), so the same
%%% module drives a plain escript proof and, later, the acme@1.0 device. The DNS
%%% side is a callback so the wildcard-capable provider (Namecheap today) is
%%% pluggable and never hard-wired here.
-module(acme_client).

-export([issue/1, letsencrypt_staging/0, letsencrypt_prod/0]).

%% DNS provider contract. set_txt/clear_txt add/remove one TXT value on
%% `_acme-challenge.<domain>'; multiple values may coexist on one name (a
%% wildcard order and its apex share the record with distinct tokens).
-callback set_txt(State :: term(), FqdnName :: binary(), Value :: binary()) ->
    {ok, term()} | {error, term()}.
-callback clear_txt(State :: term(), FqdnName :: binary(), Value :: binary()) ->
    {ok, term()} | {error, term()}.

-define(POLL_TRIES, 30).
-define(POLL_SLEEP, 3000).
-define(DNS_SETTLE, 15000).

letsencrypt_staging() ->
    <<"https://acme-staging-v02.api.letsencrypt.org/directory">>.
letsencrypt_prod() ->
    <<"https://acme-v02.api.letsencrypt.org/directory">>.

%%% -------------------------------------------------------------------------

-spec issue(map()) -> {ok, map()} | {error, term()}.
issue(Config) ->
    _ = application:ensure_all_started(inets),
    _ = application:ensure_all_started(ssl),
    AccountKey = maps:get(account_key, Config, acme_jose:gen_account_key()),
    try
        Dir = get_directory(maps:get(directory_url, Config)),
        Nonce0 = new_nonce(Dir),
        {Kid, Nonce1} = new_account(Dir, AccountKey, Config, Nonce0),
        Ids = maps:get(identifiers, Config),
        {Order, OrderUrl, Nonce2} = new_order(Dir, AccountKey, Kid, Ids, Nonce1),
        {DnsCtx, Challenges, Nonce3} =
            authorize_all(AccountKey, Kid, Order, Config, Nonce2),
        Settle = maps:get(dns_settle, Config, ?DNS_SETTLE),
        ok = log("waiting ~ps for DNS TXT to settle", [Settle div 1000]),
        timer:sleep(Settle),
        Nonce4 = trigger_and_poll(AccountKey, Kid, Challenges, Nonce3),
        {CertUrl, Nonce5} =
            finalize(AccountKey, Kid, Order, OrderUrl, Ids, Nonce4),
        {Chain, _Nonce6} = download_cert(AccountKey, Kid, CertUrl, Nonce5),
        cleanup(Config, DnsCtx),
        {CsrKeyPem, AccountPriv} = {get(cert_key_pem), maps:get(d, AccountKey)},
        {ok, #{certificate => Chain,
               certificate_key => CsrKeyPem,
               account_key_priv => AccountPriv}}
    catch
        throw:{acme_error, Reason} -> {error, Reason};
        Class:Err:St -> {error, {Class, Err, St}}
    end.

%%% ---- protocol steps -----------------------------------------------------

get_directory(Url) ->
    {200, _H, Body, _N} = http_get(Url),
    json:decode(Body).

new_nonce(#{<<"newNonce">> := Url}) ->
    {_S, Headers, _B, Nonce} = http_head(Url),
    replay_nonce(Headers, Nonce).

new_account(#{<<"newAccount">> := Url}, Key, Config, Nonce) ->
    Payload = #{<<"termsOfServiceAgreed">> => true,
                <<"contact">> => maps:get(contact, Config, [])},
    Protected = #{<<"jwk">> => acme_jose:jwk(Key),
                  <<"nonce">> => Nonce, <<"url">> => Url},
    {Status, Headers, _Body, Nonce1} = jose_post(Url, Protected, Payload, Key),
    true = (Status =:= 200) orelse (Status =:= 201),
    {header(<<"location">>, Headers), Nonce1}.

new_order(#{<<"newOrder">> := Url}, Key, Kid, Ids, Nonce) ->
    Payload = #{<<"identifiers">> =>
                    [#{<<"type">> => <<"dns">>, <<"value">> => Id} || Id <- Ids]},
    {Status, Headers, Body, Nonce1} = jose_post_kid(Url, Kid, Payload, Key, Nonce),
    true = (Status =:= 201),
    {json:decode(Body), header(<<"location">>, Headers), Nonce1}.

%% Fetch every authorization, extract its dns-01 challenge, provision the TXT.
authorize_all(Key, Kid, #{<<"authorizations">> := AuthUrls}, Config, Nonce) ->
    lists:foldl(
      fun(AuthUrl, {DnsCtx, Chals, N}) ->
              {200, _H, Body, N1} = jose_post_kid(AuthUrl, Kid, <<>>, Key, N),
              Authz = json:decode(Body),
              #{<<"identifier">> := #{<<"value">> := Domain}} = Authz,
              Chal = dns01_challenge(Authz),
              #{<<"token">> := Token, <<"url">> := ChalUrl} = Chal,
              TxtName = <<"_acme-challenge.", (strip_wild(Domain))/binary>>,
              TxtVal = acme_jose:key_authorization(Token, Key),
              {ok, DnsCtx1} = dns_call(Config, set_txt, DnsCtx, TxtName, TxtVal),
              ok = log("provisioned TXT ~s", [TxtName]),
              {DnsCtx1, [{ChalUrl, AuthUrl, TxtName, TxtVal} | Chals], N1}
      end,
      {dns_init(Config), [], Nonce}, AuthUrls).

dns01_challenge(#{<<"challenges">> := Chals}) ->
    case [C || C = #{<<"type">> := <<"dns-01">>} <- Chals] of
        [C | _] -> C;
        [] -> throw({acme_error, no_dns01_challenge})
    end.

%% Tell the CA each challenge is ready, then poll authorizations to `valid'.
trigger_and_poll(Key, Kid, Challenges, Nonce) ->
    N1 = lists:foldl(
           fun({ChalUrl, _Auth, _N, _V}, N) ->
                   {S, _H, _B, N2} = jose_post_kid(ChalUrl, Kid, #{}, Key, N),
                   true = lists:member(S, [200, 202]),
                   N2
           end, Nonce, Challenges),
    lists:foldl(
      fun({_C, AuthUrl, _N, _V}, N) ->
              poll_status(AuthUrl, Kid, Key, N, <<"valid">>,
                          [<<"invalid">>], authorization)
      end, N1, Challenges).

finalize(Key, Kid, #{<<"finalize">> := FinalizeUrl}, OrderUrl, Ids, Nonce) ->
    {CsrDer, CertKey} = acme_csr:generate(Ids),
    put(cert_key_pem, acme_csr:key_to_pem(CertKey)),
    Payload = #{<<"csr">> => acme_jose:b64u(CsrDer)},
    {S, _H, _B, N1} = jose_post_kid(FinalizeUrl, Kid, Payload, Key, Nonce),
    true = lists:member(S, [200, 202]),
    N2 = poll_status(OrderUrl, Kid, Key, N1, <<"valid">>, [<<"invalid">>], order),
    {200, _H2, Body, N3} = jose_post_kid(OrderUrl, Kid, <<>>, Key, N2),
    #{<<"certificate">> := CertUrl} = json:decode(Body),
    {CertUrl, N3}.

download_cert(Key, Kid, CertUrl, Nonce) ->
    {200, _H, Chain, N1} = jose_post_kid(CertUrl, Kid, <<>>, Key, Nonce),
    {Chain, N1}.

%% Generic status poller for authorization/order resources (POST-as-GET).
poll_status(Url, Kid, Key, Nonce, Want, Fail, What) ->
    poll_status(Url, Kid, Key, Nonce, Want, Fail, What, ?POLL_TRIES).

poll_status(_U, _K, _Ky, _N, _W, _F, What, 0) ->
    throw({acme_error, {poll_timeout, What}});
poll_status(Url, Kid, Key, Nonce, Want, Fail, What, Tries) ->
    {200, _H, Body, N1} = jose_post_kid(Url, Kid, <<>>, Key, Nonce),
    case maps:get(<<"status">>, json:decode(Body)) of
        Want -> N1;
        St ->
            case lists:member(St, Fail) of
                true -> throw({acme_error, {What, St, Body}});
                false ->
                    timer:sleep(?POLL_SLEEP),
                    poll_status(Url, Kid, Key, N1, Want, Fail, What, Tries - 1)
            end
    end.

cleanup(Config, DnsCtx) ->
    %% Best-effort TXT teardown; issuance already succeeded.
    catch lists:foldl(
            fun({_C, _A, Name, Val}, Ctx) ->
                    case dns_call(Config, clear_txt, Ctx, Name, Val) of
                        {ok, Ctx1} -> Ctx1;
                        _ -> Ctx
                    end
            end, DnsCtx, provisioned()),
    ok.

%%% ---- DNS provider dispatch ----------------------------------------------

dns_init(#{dns := {_Mod, State}}) -> State.

dns_call(#{dns := {Mod, _}}, Fun, State, Name, Val) ->
    Res = Mod:Fun(State, Name, Val),
    case {Fun, Res} of
        {set_txt, {ok, _}} ->
            put(provisioned_txts, [{x, x, Name, Val} | provisioned()]);
        _ -> ok
    end,
    Res.

provisioned() ->
    case get(provisioned_txts) of undefined -> []; L -> L end.

%%% ---- HTTP + JOSE POST helpers -------------------------------------------

jose_post(Url, Protected, Payload, Key) ->
    Body = acme_jose:jws(Protected, Payload, Key),
    http_post(Url, Body).

jose_post_kid(Url, Kid, Payload, Key, Nonce) ->
    Protected = #{<<"kid">> => Kid, <<"nonce">> => Nonce, <<"url">> => Url},
    Body = acme_jose:jws(Protected, Payload, Key),
    http_post(Url, Body).

http_get(Url) -> request(get, {b2l(Url), []}).
http_head(Url) -> request(head, {b2l(Url), []}).

http_post(Url, Body) ->
    request(post, {b2l(Url), [], "application/jose+json", Body}).

request(Method, Req) ->
    Opts = [{ssl, [{verify, verify_peer},
                   {cacerts, public_key:cacerts_get()},
                   {depth, 10}]}],
    case httpc:request(Method, Req, Opts, [{body_format, binary}]) of
        {ok, {{_V, Status, _R}, Headers, Body}} ->
            LHeaders = [{string:lowercase(K), V} || {K, V} <- Headers],
            {Status, LHeaders, Body, replay_nonce(LHeaders, undefined)};
        {error, Reason} ->
            throw({acme_error, {http, Reason}})
    end.

replay_nonce(Headers, Default) ->
    case lists:keyfind("replay-nonce", 1, Headers) of
        {_, V} -> list_to_binary(V);
        false -> Default
    end.

header(Name, Headers) ->
    case lists:keyfind(binary_to_list(Name), 1, Headers) of
        {_, V} -> list_to_binary(V);
        false -> throw({acme_error, {missing_header, Name}})
    end.

strip_wild(<<"*.", Rest/binary>>) -> Rest;
strip_wild(Name) -> Name.

b2l(B) when is_binary(B) -> binary_to_list(B);
b2l(L) -> L.

log(Fmt, Args) -> io:format("[acme] " ++ Fmt ++ "~n", Args), ok.
