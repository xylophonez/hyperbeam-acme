#!/usr/bin/env escript
%% Offline anchors for lib_acme_jose: base64url KATs, ES256 sign/verify against
%% crypto, and thumbprint/keyAuthorization determinism + shape.
%% Expects modules precompiled to ./ebin (erlc -o ebin src/*.erl).
-include_lib("public_key/include/public_key.hrl").

main(_) ->
    true = code:add_pathz("ebin"),
    ok = eq(<<>>, lib_acme_jose:b64u(<<>>), "b64u empty"),
    ok = eq(<<"Zm9vYmFy">>, lib_acme_jose:b64u(<<"foobar">>), "b64u foobar"),
    ok = eq(<<"Zg">>, lib_acme_jose:b64u(<<"f">>), "b64u pad-strip"),
    %% 0xFF -> base64 '/w==' -> urlsafe '_w': exercises the +// substitution.
    ok = eq(<<"_w">>, lib_acme_jose:b64u_int(255, 1), "b64u urlsafe /"),
    ok = eq(<<"AA">>, lib_acme_jose:b64u_int(0, 1), "b64u_int zero-pad"),

    Key = lib_acme_jose:gen_account_key(),
    #{d := Priv, x := X, y := Y} = Key,
    32 = byte_size(X), 32 = byte_size(Y),

    %% Reload from just the private scalar -> same public coordinates.
    Key2 = lib_acme_jose:account_key_from_priv(Priv),
    ok = eq(Key, Key2, "reload key from priv"),

    %% ES256 roundtrip: our raw r||s must verify under crypto (reconstruct DER).
    Msg = <<"eyJhbGciOiJFUzI1NiJ9.payload">>,
    Raw = lib_acme_jose:sign_es256(Msg, Key),
    64 = byte_size(Raw),
    <<R:256, S:256>> = Raw,
    Der = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R, s = S}),
    Pub = <<4, X/binary, Y/binary>>,
    true = crypto:verify(ecdsa, sha256, Msg, Der, [Pub, secp256r1]),
    ok = io:format("ok    ES256 sign -> crypto:verify~n"),

    %% Thumbprint + keyAuthorization: deterministic, 43-char b64u (32-byte hash).
    T1 = lib_acme_jose:thumbprint(Key),
    T2 = lib_acme_jose:thumbprint(Key2),
    ok = eq(T1, T2, "thumbprint deterministic"),
    43 = byte_size(T1),
    KA = lib_acme_jose:key_authorization(<<"tok-en_123">>, Key),
    43 = byte_size(KA),
    ok = io:format("ok    thumbprint/keyAuthorization shape~n"),

    %% JWS flattened serialization shape: protected/payload/signature present,
    %% and re-decoding the signing input verifies.
    Jws = lib_acme_jose:jws(#{<<"nonce">> => <<"n1">>, <<"url">> => <<"https://x/y">>,
                          <<"jwk">> => lib_acme_jose:jwk(Key)},
                        #{<<"termsOfServiceAgreed">> => true}, Key),
    #{<<"protected">> := P, <<"payload">> := Pl, <<"signature">> := Sg} =
        json:decode(Jws),
    SigningInput = <<P/binary, ".", Pl/binary>>,
    RawSig = b64u_decode(Sg),
    <<R2:256, S2:256>> = RawSig,
    Der2 = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R2, s = S2}),
    true = crypto:verify(ecdsa, sha256, SigningInput, Der2, [Pub, secp256r1]),
    ok = io:format("ok    JWS flattened serialization verifies~n"),

    io:format("~nALL JOSE CHECKS PASSED~n").

eq(A, A, _) -> ok;
eq(Exp, Got, What) ->
    io:format("FAIL  ~s~n  expected: ~p~n  got:      ~p~n", [What, Exp, Got]),
    halt(1).

b64u_decode(B) ->
    Pad = case byte_size(B) rem 4 of 0 -> <<>>; 2 -> <<"==">>; 3 -> <<"=">> end,
    S1 = binary:replace(B, <<"-">>, <<"+">>, [global]),
    S2 = binary:replace(S1, <<"_">>, <<"/">>, [global]),
    base64:decode(<<S2/binary, Pad/binary>>).
