- The directory believes at most `AC_DIRECTORY_TRUSTED_HOPS` (new, default
  1) entries of the client-address header, from the right. A client whose
  own address was inside a listed proxy block (a shared CDN range) could
  prepend addresses and pick its rate-limit bucket. Behind a chain of your
  own proxies, set it to their number; behind a CDN, keep it at 1 and let
  your proxy take the address from the CDN's own header (directory README,
  "Behind a CDN"; the relay docs say the same for `AC_RELAY_PROXY_HOPS`)
  (SR-22).
