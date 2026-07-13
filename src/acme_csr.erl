%%% PKCS#10 CSR generation for ACME finalize (RFC 8555 §7.4).
%%%
%%% Self-contained: a small DER encoder plus crypto, so no openssl dependency
%%% inside the node. Produces an EC P-256 CSR whose SubjectAltName carries every
%%% requested dNSName (the wildcard and its apex), which is what a DNS-01 order
%%% finalizes against.
-module(acme_csr).

-export([generate/1, generate/2, key_to_pem/1]).

%% Returns the DER CSR (ACME wants base64url of this) and the freshly generated
%% certificate key, kept as the same #{d,x,y} map shape acme_jose uses.
-spec generate([binary()]) -> {CsrDer :: binary(), acme_jose:key()}.
generate(Dnsnames) ->
    generate(Dnsnames, acme_jose:gen_account_key()).

-spec generate([binary()], acme_jose:key()) -> {binary(), acme_jose:key()}.
generate([_ | _] = Dnsnames, #{d := Priv, x := X, y := Y} = Key) ->
    Point = <<4, X/binary, Y/binary>>,
    SpkiAlg = seq([oid([1,2,840,10045,2,1]),          % id-ecPublicKey
                   oid([1,2,840,10045,3,1,7])]),       % prime256v1
    Spki = seq([SpkiAlg, bit_string(Point)]),
    Subject = subject_cn(hd(Dnsnames)),
    Attrs = attributes(Dnsnames),
    CriDer = seq([integer(0), Subject, Spki, Attrs]),  % version v1(0)
    SigAlg = seq([oid([1,2,840,10045,4,3,2])]),        % ecdsa-with-SHA256
    Sig = crypto:sign(ecdsa, sha256, CriDer, [Priv, secp256r1]),
    Csr = seq([CriDer, SigAlg, bit_string(Sig)]),
    {Csr, Key}.

%% SEC1 PEM for the cert key, so it can be stored next to the issued chain and
%% loaded by a TLS terminator later.
-spec key_to_pem(acme_jose:key()) -> binary().
key_to_pem(#{d := Priv, x := X, y := Y}) ->
    EcKey = seq([integer(1),
                 der(16#04, Priv),                                   % privateKey OCTET STRING
                 der(16#A0, oid([1,2,840,10045,3,1,7])),             % [0] namedCurve
                 der(16#A1, bit_string(<<4, X/binary, Y/binary>>))]),% [1] publicKey
    public_key:pem_encode([{'ECPrivateKey', EcKey, not_encrypted}]).

%%% ---- CSR sub-structures -------------------------------------------------

subject_cn(Cn) ->
    Atv = seq([oid([2,5,4,3]), utf8_string(strip_wild(Cn))]),  % commonName
    seq([set([Atv])]).                                          % rdnSequence

%% A wildcard label isn't a valid CN; use the apex there but keep the wildcard
%% (and every name) in the SAN, which is what CAs actually validate.
strip_wild(<<"*.", Rest/binary>>) -> Rest;
strip_wild(Name) -> Name.

attributes(Dnsnames) ->
    GeneralNames = seq([der(16#82, N) || N <- Dnsnames]),  % [2] dNSName IA5String
    SanExt = seq([oid([2,5,29,17]),                        % subjectAltName
                  der(16#04, GeneralNames)]),              % extnValue OCTET STRING
    ExtReq = seq([oid([1,2,840,113549,1,9,14]),            % extensionRequest
                  set([seq([SanExt])])]),
    der(16#A0, ExtReq).                                    % [0] IMPLICIT attributes

%%% ---- minimal DER encoder ------------------------------------------------

seq(Items) -> der(16#30, iolist_to_binary(Items)).
set(Items) -> der(16#31, iolist_to_binary(Items)).

integer(N) when N >= 0 ->
    Bytes = binary:encode_unsigned(N),
    %% DER INTEGER is signed: prepend 0x00 if the top bit is set.
    Body = case Bytes of
               <<H, _/binary>> when H >= 16#80 -> <<0, Bytes/binary>>;
               <<>> -> <<0>>;
               _ -> Bytes
           end,
    der(16#02, Body).

bit_string(Bin) -> der(16#03, <<0, Bin/binary>>).   % 0 unused bits
utf8_string(Bin) -> der(16#0C, Bin).

oid([A, B | Rest]) ->
    First = <<(40 * A + B)>>,
    Body = iolist_to_binary([First | [oid_arc(N) || N <- Rest]]),
    der(16#06, Body).

oid_arc(N) when N < 128 -> <<N>>;
oid_arc(N) -> oid_arc_hi(N bsr 7, [<<(N band 16#7f)>>]).
oid_arc_hi(0, Acc) -> iolist_to_binary(Acc);
oid_arc_hi(N, Acc) -> oid_arc_hi(N bsr 7, [<<((N band 16#7f) bor 16#80)>> | Acc]).

der(Tag, Content) when is_binary(Content) ->
    <<Tag, (der_len(byte_size(Content)))/binary, Content/binary>>.

der_len(L) when L < 16#80 -> <<L>>;
der_len(L) ->
    Bytes = binary:encode_unsigned(L),
    <<(16#80 bor byte_size(Bytes)), Bytes/binary>>.
