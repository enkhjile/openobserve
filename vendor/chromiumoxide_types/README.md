# Chromiumoxide protocol decoder compatibility patch

Source: https://github.com/mattsse/chromiumoxide/tree/6f2392f78ae851e2acf33df8e9764cc299d837db/chromiumoxide_types
Package version: 0.7.0. Original MIT and Apache-2.0 licenses are retained.

OpenObserve enables `serde_json/arbitrary_precision`. Serde's untagged enum content buffer cannot replay fractional JSON numbers as `f64` in this configuration. The pinned `Message` decoder consequently discards `Page.lifecycleEvent` timestamps, and Chrome navigation never completes. Decode the envelope through `serde_json::Value` before decoding the response/event; retain all numeric precision and the existing protocol types.

The only functional upstream delta is `Message` deserialization. Regression tests cover fractional event timestamps, ordinary responses and malformed envelopes. Run `cargo test --manifest-path vendor/chromiumoxide_types/Cargo.toml --offline`.

Retire this patch when the pinned Chromiumoxide revision includes a compatible decoder: run these same regressions against that revision and the scoped browser/PDF/SMTP smoke test, then remove this directory and the root Git-source patch together. Do not remove OpenObserve's arbitrary-precision feature to work around protocol decoding.
