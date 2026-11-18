# :integration-tests

End-to-end test of the product's core path against a **real kernel WireGuard peer**:

```
SshjTransport --LoopbackPreamble(port, token)--> 127.0.0.1 forwarder
   -> libwgbridge (userspace wireguard-go) --UDP--> kernel wireguard (tmxwg0, 10.99.0.1)
   -> embedded Apache MINA SSHD bound to 10.99.0.1
```

`TunnelEndToEndTest` checks: SSH exec and a shell round-trip over the tunnel; the host-key
verifier is asked about `router.e2e.invalid` (a name that never resolves); tunnel stats show a
handshake and non-zero rx/tx; a connection with a wrong token gets no SSH banner and is closed;
`rebind()` followed by a new forward works; `close()` is idempotent.

The tests do nothing unless `TMX_E2E=1`. With it set they need:

| Variable | Meaning |
| --- | --- |
| `TMX_WG_CONFIG` | path of the client wg-quick config |
| `TMX_WGBRIDGE_LIB` | absolute path of `libwgbridge.so` (set as `terminalmax.wgbridge.path`) |
| `TMX_WG_SERVER_IP` | kernel peer address, default `10.99.0.1` |

CI (`e2e-tunnel` job in `.github/workflows/ci.yml`) builds the library with
`native/wgbridge/build-desktop.sh` (linux/amd64), creates `tmxwg0` with `ip link add ... type
wireguard`, generates two key pairs, assigns `10.99.0.1/24`, writes the client config and runs
`TMX_E2E=1 ./gradlew :integration-tests:test`. If the runner cannot create a WireGuard interface
the job fails with an explicit error (it never skips).

To run locally on Linux (needs root for the interface): create the interface and config the same
way, build `native/wgbridge/out/linux-x64/libwgbridge.so`, export the variables above and run
the Gradle command.
