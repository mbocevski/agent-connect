- After the operator rotates its token key (`AC_DIRECTORY_TOKEN_KEYS`), the
  directory treats a stored listing whose token is under a key it no longer
  pins as expired (`410 Gone`, out of search and the index) instead of
  serving one knockers refuse. It records each listing's token key at
  publish (a schema migration adds the column; maintenance fills it in for
  existing listings), so nothing is re-verified on a request. A daemon whose
  renewal is refused with `unknown_key` retries while it still pins the
  token's key (the directory lags) and stops, telling its human
  (`listing_stale`, `reason: refused`), once it doesn't either (SR-24).
