# MarketplaceCore

Marketplace for the XMR Token Overlay Protocol. Client communications, notifications, market-based operations.

.NET 10. Copy `appsettings.example.json` to `appsettings.json` and set the marketplace, indexer URL, public HTTPS origin and allowed browser origins.

Native signature verification uses `xtop_monero.dll` on Windows or `libxtop_monero.so` on Linux. Sources are included in [`Native`](Native): XTOP wrappers and [Monero v0.18.5.1](https://github.com/monero-project/monero/tree/v0.18.5.1). Source hashes: [`SOURCES.json`](Native/vendor/monero/SOURCES.json). Build with `Native/setup.ps1`, then `Native/build.ps1` on Windows, or `sh Native/build-linux.sh` on Linux with a C compiler installed.

Run: `dotnet run`. HTTPS is required outside Development. Local HTTP: `dotnet run -- --environment Development --urls http://127.0.0.1:5082`.

| Method | Route | Result |
| --- | --- | --- |
| GET | `/api/communication` | Network, marketplace, protocol and channel limits |
| GET | `/api/communication/listings/{listingId}/availability` | Listing eligibility and seller presence |
| WebSocket | `/hubs/communication` | SignalR JSON protocol for authenticated key exchange and ciphertext relay |
