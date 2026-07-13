%%% Certificate material <-> TLS listener options.
%%%
%%% The one piece of M2 (termination) that is pure OTP and testable without
%%% cowboy or a running node: turn a stored PEM chain + key into the ssl options
%%% a listener needs, and answer "does this cert need renewing yet?". Persistence
%%% is the caller's job (the device uses hb_store; tests use files) so this stays
%%% dependency-free.
-module(acme_store).

-include_lib("public_key/include/public_key.hrl").

-export([tls_opts/2, leaf_cert/1, not_after/1, needs_renewal/2]).

%% ssl options for a TLS listener terminating with this cert. The chain PEM is
%% leaf-first (as ACME returns it): the head is the server cert, the tail are
%% intermediates offered to clients via `cacerts'.
-spec tls_opts(ChainPem :: binary(), KeyPem :: binary()) -> [ssl:tls_server_option()].
tls_opts(ChainPem, KeyPem) ->
    [LeafDer | ChainDers] = cert_ders(ChainPem),
    {KeyType, KeyDer} = key_entry(KeyPem),
    [{cert, LeafDer},
     {key, {KeyType, KeyDer}},
     {cacerts, ChainDers},
     {versions, ['tlsv1.2', 'tlsv1.3']}].

-spec leaf_cert(binary()) -> #'OTPCertificate'{}.
leaf_cert(ChainPem) ->
    [LeafDer | _] = cert_ders(ChainPem),
    public_key:pkix_decode_cert(LeafDer, otp).

%% Leaf notAfter as a UTC {{Y,M,D},{H,Mi,S}} tuple.
-spec not_after(binary()) -> calendar:datetime().
not_after(ChainPem) ->
    Cert = leaf_cert(ChainPem),
    Validity = (Cert#'OTPCertificate'.tbsCertificate)#'OTPTBSCertificate'.validity,
    asn1_time(Validity#'Validity'.'notAfter').

%% Renew when fewer than RenewDays remain (Let's Encrypt certs live 90 days;
%% 30 is the conventional threshold). `Now' is passed in — this module never
%% reads the clock, so it stays deterministic and testable.
-spec needs_renewal(binary(), {calendar:datetime(), pos_integer()}) -> boolean().
needs_renewal(ChainPem, {Now, RenewDays}) ->
    Secs = calendar:datetime_to_gregorian_seconds(not_after(ChainPem))
         - calendar:datetime_to_gregorian_seconds(Now),
    Secs < RenewDays * 86400.

%%% ---- internals ----------------------------------------------------------

cert_ders(Pem) ->
    case [Der || {'Certificate', Der, not_encrypted} <- public_key:pem_decode(Pem)] of
        [] -> error(no_certificates_in_pem);
        Ders -> Ders
    end.

%% ACME returns an EC (or RSA) key; ssl's `key' option is {Type, DER}. A PEM may
%% carry other blocks first (e.g. `EC PARAMETERS`), so scan for the key entry.
key_entry(Pem) ->
    Keys = [{Type, Der} || {Type, Der, not_encrypted} <- public_key:pem_decode(Pem),
                           lists:member(Type, ['ECPrivateKey', 'RSAPrivateKey',
                                               'PrivateKeyInfo'])],
    case Keys of
        [KeyEntry | _] -> KeyEntry;
        [] -> error(no_private_key_in_pem)
    end.

asn1_time({utcTime, T}) -> asn1_time({generalTime, "20" ++ T});
asn1_time({generalTime, T}) ->
    <<Y:4/binary, Mo:2/binary, D:2/binary, H:2/binary, Mi:2/binary, S:2/binary, _/binary>> =
        list_to_binary(T),
    {{b2i(Y), b2i(Mo), b2i(D)}, {b2i(H), b2i(Mi), b2i(S)}}.

b2i(B) -> binary_to_integer(B).
