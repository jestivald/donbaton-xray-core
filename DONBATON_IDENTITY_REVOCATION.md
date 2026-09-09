# VLESS identity revocation

Base: XTLS/Xray-core v26.7.28, commit 5ca6f4b7d4dc20a881d4330e498892697627ec0c.

RemoveUser now invalidates the credential and closes its authenticated logical
connections on that inbound. A mutex and a validator generation check prevent a
connection authenticated before removal from registering afterwards. Removal and
normal completion release the registry entries. Handler.Close closes all entries.
Other users and the same credential on another inbound are independent.

For XHTTP the tracked connection is the split HTTP session. A stalled response
write is interrupted using the response write deadline before waiting for its
write mutex. HTTP/2 implements this deadline on the individual stream. An idle
writer closes normally without changing a deadline. No source-IP socket killing
or shared reverse-proxy connection lookup is involved.

Build with Go 1.26.5 and the unchanged go.mod/go.sum:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w' -o xray ./main
go test ./proxy/vless/... ./transport/internet/splithttp
go test -race ./proxy/vless/inbound ./transport/internet/splithttp -run 'Test(RemoveUser|Registration|CloseRuns|NormalCompletion|CloseHandler|UnknownRemoval|ConcurrentCleanup|LogicalConnection)' -count=5
```

Validation: targeted revocation tests pass with race detection; full VLESS/XHTTP
regressions pass without race detection. Full upstream XHTTP race tests also fail
on the clean base in client.go WaitReadCloser; this fork does not claim they pass.
Two 60-second real-binary loopback runs cover raw/XHTTP packet-up, with and without
raw inner MUX. Removed users' open LTE streams stop and new requests fail; their
Wi-Fi and another user's streams continue. Restoring the same credentials works.
Inner MUX over XHTTP failed baseline on both upstream and candidate and is excluded
from that claim. XHTTP's own transport multiplexing is separate.

This patch applies to VLESS. Initial deployment is scoped to the two VLESS LTE
nodes and must be paired with Node's opt-in identity revocation mode. Before live
cutover, exercise the exact TLS/REALITY/CDN routes with synthetic users. Existing
production client credentials are not test fixtures.

The API is unchanged. To quiesce an inbound, fence additions/restarts, remove every
loaded user, verify the count stays zero and authenticated traffic counters stop
growing. Do not restart Xray or reset traffic counters during the drain. Restore
from current panel membership through Node, not an old user snapshot.
