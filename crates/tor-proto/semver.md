BREAKING: `CongestionParams::use_fallback_alg()` is no longer public.
BREAKING: `ClientCirc::extend_virtual()` now takes parameters by reference,
  and a list of Protocol capabilities
BREAKING: Renamed `StreamReader` to `StreamReceiver`. Although the type is
  public, there is no public way to create or access one.
BREAKING: Removed `StreamReceiver::recv`. Although the type is public,
  there is no public way to create or access one.
