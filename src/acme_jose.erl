%%% JOSE/JWS primitives for an ACME (RFC 8555) client.
%%%
%%% Deliberately dependency-free: only crypto/public_key, so it can run
%%% unchanged inside a HyperBEAM/LapEE node or a plain escript. All ACME
%%% signing is ES256 (ECDSA P-256 + SHA-256), the algorithm every ACME CA
%%% supports and the smallest to carry in an attested image.
-module(acme_jose).

-include_lib("public_key/include/public_key.hrl").

-export([b64u/1, b64u_int/2, gen_account_key/0, account_key_from_priv/1,
         jwk/1, thumbprint/1, key_authorization/2, sign_es256/2,
         jws/3, jws/4]).

%% An account/cert key is kept as a plain map so it serialises cleanly into
%% the node's store: #{d := <priv scalar>, x := <32 bytes>, y := <32 bytes>}.
-type key() :: #{d := binary(), x := binary(), y := binary()}.
-export_type([key/0]).

%%% ---- base64url (RFC 4648 §5, no padding) --------------------------------

-spec b64u(binary()) -> binary().
b64u(Bin) when is_binary(Bin) ->
    Enc = base64:encode(Bin),
    Stripped = binary:replace(Enc, <<"=">>, <<>>, [global]),
    S1 = binary:replace(Stripped, <<"+">>, <<"-">>, [global]),
    binary:replace(S1, <<"/">>, <<"_">>, [global]).

%% Encode a non-negative integer as a fixed-width big-endian byte string,
%% then base64url. Used for EC coordinates and ECDSA r/s (each 32 bytes on
%% P-256), where fixed width is mandatory (RFC 7518 §6.2.1.2).
-spec b64u_int(non_neg_integer(), pos_integer()) -> binary().
b64u_int(Int, Width) when is_integer(Int), Int >= 0 ->
    b64u(pad_left(binary:encode_unsigned(Int), Width)).

pad_left(Bin, Width) when byte_size(Bin) =:= Width -> Bin;
pad_left(Bin, Width) when byte_size(Bin) < Width ->
    pad_left(<<0, Bin/binary>>, Width);
pad_left(Bin, Width) ->
    %% Too long only if a leading zero byte crept in; drop it.
    <<0, Rest/binary>> = Bin,
    pad_left(Rest, Width).

%%% ---- key handling -------------------------------------------------------

-spec gen_account_key() -> key().
gen_account_key() ->
    {Pub, Priv} = crypto:generate_key(ecdh, secp256r1),
    account_key_from_parts(Pub, Priv).

%% Rebuild the public point from a stored private scalar, so a key persisted
%% as just its `d' can be reloaded.
-spec account_key_from_priv(binary()) -> key().
account_key_from_priv(Priv) when is_binary(Priv) ->
    {Pub, Priv} = crypto:generate_key(ecdh, secp256r1, Priv),
    account_key_from_parts(Pub, Priv).

account_key_from_parts(<<4, X:32/binary, Y:32/binary>>, Priv) ->
    #{d => Priv, x => X, y => Y}.

%% Public JWK (RFC 7518 §6.2.1). Insertion order here is irrelevant to JSON
%% output but MUST be lexicographic for the thumbprint; see thumbprint/1.
-spec jwk(key()) -> #{binary() => binary()}.
jwk(#{x := X, y := Y}) ->
    #{<<"crv">> => <<"P-256">>,
      <<"kty">> => <<"EC">>,
      <<"x">> => b64u(X),
      <<"y">> => b64u(Y)}.

%% RFC 7638 JWK thumbprint: SHA-256 over the canonical JSON of the required
%% members only, keys in lexicographic order, no whitespace.
-spec thumbprint(key()) -> binary().
thumbprint(Key) ->
    #{<<"crv">> := Crv, <<"kty">> := Kty, <<"x">> := X, <<"y">> := Y} = jwk(Key),
    Canonical = <<"{\"crv\":\"", Crv/binary, "\",\"kty\":\"", Kty/binary,
                  "\",\"x\":\"", X/binary, "\",\"y\":\"", Y/binary, "\"}">>,
    b64u(crypto:hash(sha256, Canonical)).

%% ACME dns-01 keyAuthorization -> TXT value (RFC 8555 §8.4):
%% TXT = base64url(SHA-256(token || "." || base64url-thumbprint)).
-spec key_authorization(binary(), key()) -> binary().
key_authorization(Token, Key) ->
    KeyAuth = <<Token/binary, ".", (thumbprint(Key))/binary>>,
    b64u(crypto:hash(sha256, KeyAuth)).

%%% ---- signing ------------------------------------------------------------

%% ES256 over Msg. crypto:sign yields a DER ECDSA-Sig-Value; JOSE wants the
%% raw r||s concatenation, each coordinate fixed at 32 bytes.
-spec sign_es256(iodata(), key()) -> binary().
sign_es256(Msg, #{d := Priv}) ->
    Der = crypto:sign(ecdsa, sha256, Msg, [Priv, secp256r1]),
    #'ECDSA-Sig-Value'{r = R, s = S} =
        public_key:der_decode('ECDSA-Sig-Value', Der),
    <<(pad_left(binary:encode_unsigned(R), 32))/binary,
      (pad_left(binary:encode_unsigned(S), 32))/binary>>.

%%% ---- JWS (flattened JSON serialization, RFC 7515 §7.2.2) ----------------

%% Build the JWS object ACME posts as the request body. `Protected' is the
%% caller-supplied header map (alg is injected); it carries either `jwk'
%% (newAccount) or `kid' (everything after), plus `nonce' and `url'.
-spec jws(#{atom() | binary() => term()}, iodata() | map(), key()) -> binary().
jws(Protected, Payload, Key) ->
    jws(Protected, Payload, Key, #{}).

-spec jws(map(), iodata() | map(), key(), map()) -> binary().
jws(Protected0, Payload, Key, _Opts) ->
    Protected = Protected0#{<<"alg">> => <<"ES256">>},
    ProtectedB64 = b64u(iolist_to_binary(json_encode(Protected))),
    PayloadB64 = encode_payload(Payload),
    Signing = <<ProtectedB64/binary, ".", PayloadB64/binary>>,
    Sig = b64u(sign_es256(Signing, Key)),
    iolist_to_binary(json_encode(#{<<"protected">> => ProtectedB64,
                                   <<"payload">> => PayloadB64,
                                   <<"signature">> => Sig})).

%% ACME POST-as-GET uses an empty-string payload; a map is JSON-encoded.
encode_payload(<<>>) -> <<>>;
encode_payload(Map) when is_map(Map) -> b64u(iolist_to_binary(json_encode(Map)));
encode_payload(Bin) when is_binary(Bin) -> b64u(Bin).

%% Minimal JSON encoder. OTP 27 ships `json'; fall back for portability.
json_encode(Term) ->
    case erlang:function_exported(json, encode, 1) of
        true -> json:encode(Term);
        false -> legacy_json(Term)
    end.

legacy_json(Map) when is_map(Map), map_size(Map) =:= 0 -> "{}";
legacy_json(Map) when is_map(Map) ->
    Pairs = [[$", esc(K), $", $:, legacy_json(V)] || {K, V} <- maps:to_list(Map)],
    [${, lists:join($,, Pairs), $}];
legacy_json(List) when is_list(List) ->
    [$[, lists:join($,, [legacy_json(V) || V <- List]), $]];
legacy_json(Bin) when is_binary(Bin) -> [$", esc(Bin), $"];
legacy_json(Int) when is_integer(Int) -> integer_to_list(Int);
legacy_json(true) -> "true";
legacy_json(false) -> "false";
legacy_json(null) -> "null".

esc(Bin) when is_binary(Bin) -> Bin;
esc(Atom) when is_atom(Atom) -> atom_to_binary(Atom, utf8).
