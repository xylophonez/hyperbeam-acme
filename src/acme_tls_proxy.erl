%%% cowboy handler: faithfully relay one HTTPS request to the node's local
%%% cleartext listener and relay the response back verbatim.
%%%
%%% Faithfulness is the whole point (the tunnel work learned this the hard way):
%%% the Host header is preserved so the provider still routes public traffic to
%%% the right registered node, status/redirects/content-types/bodies of any size
%%% pass through untouched. Hop-by-hop headers are stripped per RFC 7230 §6.1.
-module(acme_tls_proxy).

-export([init/2]).

-define(HOP_BY_HOP, [<<"connection">>, <<"keep-alive">>, <<"proxy-authenticate">>,
                     <<"proxy-authorization">>, <<"te">>, <<"trailer">>,
                     <<"transfer-encoding">>, <<"upgrade">>, <<"content-length">>]).

init(Req0, State = #{clear_host := CHost, clear_port := CPort}) ->
    Method = cowboy_req:method(Req0),
    Path = full_path(Req0),
    ReqHeaders = strip_hop_by_hop(cowboy_req:headers(Req0)),
    {ok, Body, Req1} = read_body(Req0, <<>>),
    case proxy(CHost, CPort, Method, Path, ReqHeaders, Body) of
        {ok, Status, RespHeaders, RespBody} ->
            Clean = maps:without([<<"transfer-encoding">>, <<"content-length">>],
                                 maps:from_list(lower(RespHeaders))),
            Req2 = cowboy_req:reply(Status, Clean, RespBody, Req1),
            {ok, Req2, State};
        {error, Reason} ->
            Req2 = cowboy_req:reply(502, #{<<"content-type">> => <<"text/plain">>},
                                    io_lib:format("acme tls proxy: ~p", [Reason]), Req1),
            {ok, Req2, State}
    end.

full_path(Req) ->
    case cowboy_req:qs(Req) of
        <<>> -> cowboy_req:path(Req);
        Qs -> <<(cowboy_req:path(Req))/binary, "?", Qs/binary>>
    end.

read_body(Req0, Acc) ->
    case cowboy_req:read_body(Req0) of
        {ok, Data, Req} -> {ok, <<Acc/binary, Data/binary>>, Req};
        {more, Data, Req} -> read_body(Req, <<Acc/binary, Data/binary>>)
    end.

%% Single buffered round-trip to the local clear listener over gun.
proxy(Host, Port, Method, Path, Headers, Body) ->
    HdrList = maps:to_list(Headers),
    case gun:open(binary_to_list_host(Host), Port, #{transport => tcp,
                                                     protocols => [http],
                                                     retry => 0}) of
        {ok, Conn} ->
            try
                {ok, http} = gun:await_up(Conn, 5000),
                Ref = gun:request(Conn, Method, Path, HdrList, Body),
                case gun:await(Conn, Ref, 60000) of
                    {response, fin, Status, RHdrs} ->
                        {ok, Status, RHdrs, <<>>};
                    {response, nofin, Status, RHdrs} ->
                        {ok, RBody} = gun:await_body(Conn, Ref, 60000),
                        {ok, Status, RHdrs, RBody};
                    {error, R} -> {error, R}
                end
            catch _:E -> {error, E}
            after gun:close(Conn)
            end;
        {error, R} -> {error, R}
    end.

strip_hop_by_hop(Headers) ->
    maps:without(?HOP_BY_HOP, Headers).

lower(Headers) -> [{string:lowercase(K), V} || {K, V} <- Headers].

binary_to_list_host(H) when is_binary(H) -> binary_to_list(H);
binary_to_list_host(H) -> H.
