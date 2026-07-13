%%% Namecheap DNS-01 provider for acme_client.
%%%
%%% CRITICAL: Namecheap's setHosts REPLACES the entire record set for a domain.
%%% Every mutation here is read-modify-write (getHosts -> edit -> setHosts) so
%%% the tunnel's own A/CNAME records are never clobbered. The caller's public IP
%%% must be whitelisted in the Namecheap API console; in production this runs on
%%% the provider LapEE, whose IP is already whitelisted.
-module(acme_dns_namecheap).
-behaviour(acme_client).

-export([new/1, set_txt/3, clear_txt/3, clear_name/2, ensure_a/3]).

%% State: the API credentials plus the SLD/TLD split of the managed domain.
%% #{api_user, api_key, username, client_ip, sld, tld}
-spec new(map()) -> map().
new(#{api_key := _, domain := Domain} = C) ->
    _ = application:ensure_all_started(inets),
    _ = application:ensure_all_started(ssl),
    [Sld, Tld] = binary:split(Domain, <<".">>),
    ApiUser = maps:get(api_user, C, maps:get(username, C)),
    #{api_user => to_bin(ApiUser),
      api_key => to_bin(maps:get(api_key, C)),
      username => to_bin(maps:get(username, C, ApiUser)),
      client_ip => to_bin(maps:get(client_ip, C)),
      sld => Sld, tld => Tld}.

set_txt(State, FqdnName, Value) ->
    Host = host_label(FqdnName, State),
    modify(State, fun(Hosts) ->
        %% Idempotent add: drop an identical prior entry, then append.
        Kept = [H || H <- Hosts, not same_txt(H, Host, Value)],
        Kept ++ [#{name => Host, type => <<"TXT">>, address => Value, ttl => <<"60">>}]
    end).

clear_txt(State, FqdnName, Value) ->
    Host = host_label(FqdnName, State),
    modify(State, fun(Hosts) ->
        [H || H <- Hosts, not same_txt(H, Host, Value)]
    end).

%% Point a name's A record at Ip (read-modify-write; replaces any existing A at
%% that name). Lets a self-hosting node publish its own wildcard + apex records
%% so DNS points at itself — the last piece of DNS self-bootstrap alongside the
%% dns-01 TXT. Idempotent.
ensure_a(State, FqdnName, Ip) ->
    Host = host_label(FqdnName, State),
    modify(State, fun(Hosts) ->
        Kept = [H || H <- Hosts,
                     not (maps:get(name, H) =:= Host andalso maps:get(type, H) =:= <<"A">>)],
        Kept ++ [#{name => Host, type => <<"A">>, address => Ip, ttl => <<"300">>}]
    end).

%% Remove every TXT record at a name in one write (idempotent teardown).
clear_name(State, FqdnName) ->
    Host = host_label(FqdnName, State),
    modify(State, fun(Hosts) ->
        [H || H <- Hosts,
              not (maps:get(name, H) =:= Host andalso maps:get(type, H) =:= <<"TXT">>)]
    end).

%%% -------------------------------------------------------------------------

%% `_acme-challenge.tunnel.permaweb.space' with managed domain permaweb.space
%% -> host label `_acme-challenge.tunnel'.
host_label(Fqdn, #{sld := Sld, tld := Tld}) ->
    Domain = <<Sld/binary, ".", Tld/binary>>,
    Suffix = <<".", Domain/binary>>,
    case binary:match(Fqdn, Suffix) of
        {Pos, Len} when Pos + Len =:= byte_size(Fqdn) ->
            binary:part(Fqdn, 0, Pos);
        _ when Fqdn =:= Domain -> <<"@">>;
        _ -> Fqdn
    end.

same_txt(#{name := N, type := <<"TXT">>, address := A}, N, A) -> true;
same_txt(_, _, _) -> false.

modify(State, Fun) ->
    case get_hosts(State) of
        {ok, Hosts} ->
            NewHosts = Fun(Hosts),
            set_hosts(State, NewHosts);
        {error, _} = E -> E
    end.

%%% ---- Namecheap API (getHosts / setHosts) --------------------------------

get_hosts(State) ->
    Query = base_query(State, <<"namecheap.domains.dns.getHosts">>),
    case api_get(Query) of
        {ok, Xml} -> {ok, parse_hosts(Xml)};
        {error, _} = E -> E
    end.

set_hosts(State, Hosts) ->
    HostParams = lists:append(
        [host_params(I, H) || {I, H} <- lists:zip(lists:seq(1, length(Hosts)), Hosts)]),
    %% base_query already carries SLD/TLD once; Namecheap rejects duplicates.
    Query = base_query(State, <<"namecheap.domains.dns.setHosts">>) ++ HostParams,
    case api_get(Query) of
        {ok, Xml} ->
            case binary:match(Xml, <<"IsSuccess=\"true\"">>) of
                nomatch -> {error, {setHosts_failed, first_error(Xml)}};
                _ -> {ok, State}
            end;
        {error, _} = E -> E
    end.

host_params(I, #{name := N, type := T, address := A} = H) ->
    Ttl = maps:get(ttl, H, <<"1800">>),
    Idx = integer_to_binary(I),
    [{<<"HostName", Idx/binary>>, N},
     {<<"RecordType", Idx/binary>>, T},
     {<<"Address", Idx/binary>>, A},
     {<<"TTL", Idx/binary>>, Ttl}].

base_query(#{api_user := U, api_key := K, username := Un, client_ip := Ip,
             sld := Sld, tld := Tld}, Command) ->
    [{<<"ApiUser">>, U}, {<<"ApiKey">>, K}, {<<"UserName">>, Un},
     {<<"ClientIp">>, Ip}, {<<"Command">>, Command},
     {<<"SLD">>, Sld}, {<<"TLD">>, Tld}].

api_get(Query) ->
    Url = <<"https://api.namecheap.com/xml.response?", (urlencode(Query))/binary>>,
    Opts = [{ssl, [{verify, verify_peer}, {cacerts, public_key:cacerts_get()}]}],
    case httpc:request(get, {binary_to_list(Url), []}, Opts, [{body_format, binary}]) of
        {ok, {{_, 200, _}, _H, Body}} -> {ok, Body};
        {ok, {{_, S, _}, _H, Body}} -> {error, {http, S, Body}};
        {error, R} -> {error, {http, R}}
    end.

%%% ---- tiny XML extraction (host records only) ----------------------------

%% Namecheap getHosts returns <host Name=".." Type=".." Address=".." TTL=".."/>.
%% We only need those four attributes; a full XML parser would be overkill and
%% another dependency inside the node.
parse_hosts(Xml) ->
    case re:run(Xml, "<host\\b[^>]*/>", [global, {capture, all, binary}]) of
        {match, Tags} -> [host_from_tag(T) || [T] <- Tags];
        nomatch -> []
    end.

host_from_tag(Tag) ->
    #{name => attr(Tag, "Name"),
      type => attr(Tag, "Type"),
      address => attr(Tag, "Address"),
      ttl => attr(Tag, "TTL")}.

attr(Tag, Name) ->
    case re:run(Tag, Name ++ "=\"([^\"]*)\"", [{capture, [1], binary}]) of
        {match, [V]} -> V;
        nomatch -> <<>>
    end.

first_error(Xml) ->
    case re:run(Xml, "<Error[^>]*>([^<]*)</Error>", [{capture, [1], binary}]) of
        {match, [E]} -> E;
        nomatch -> Xml
    end.

%%% ---- helpers ------------------------------------------------------------

urlencode(Pairs) ->
    iolist_to_binary(lists:join(<<"&">>,
        [[K, <<"=">>, http_uri_encode(V)] || {K, V} <- Pairs])).

http_uri_encode(V) ->
    list_to_binary(uri_string:quote(binary_to_list(to_bin(V)))).

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L) -> list_to_binary(L);
to_bin(A) when is_atom(A) -> atom_to_binary(A, utf8).
