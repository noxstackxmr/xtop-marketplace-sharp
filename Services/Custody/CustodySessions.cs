using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using MarketplaceCore.Crypto;
using MarketplaceCore.Models;
using MarketplaceCore.Monero;
using MarketplaceCore.Options;
using MarketplaceCore.Services.Indexer;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Custody;

public sealed class CustodySessions(CustodyKeys keys, CustodyProofs proofs, ICustodyDirectory directory,
    ICustodyNode node, ICustodySignerFactory signers, CustodyJournal journal, IOptions<MarketplaceOptions> marketplace,
    IOptions<CustodyOptions> custody, TimeProvider clock, ILogger<CustodySessions> logger,
    CustodyResources resources, CustodySettlement settlement) : BackgroundService
{
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    private readonly Dictionary<string, string> reservations = [];
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private bool stopping;
    private readonly CancellationTokenSource shutdown = new();
    private long Now => clock.GetUtcNow().ToUnixTimeSeconds();

    public static byte[] RequestHash(CustodyOpen request, MarketplaceOptions market) => MoneroProofCrypto.Hash(
        JsonSerializer.SerializeToUtf8Bytes(new { domain = "XTOP:CUSTODY:OPEN:V1", network = market.NetworkId, marketplace = market.Id,
            origin = market.PublicOrigin, request.Operation, request.Reference, request.ConfigHash, request.OwnerKey,
            request.EncryptionKey, request.Nonce, request.ExpiresAt }, Json));

    public async Task<CustodyHandshake> OpenAsync(CustodyOpen request, CancellationToken cancellationToken)
    {
        if (!keys.Enabled) throw new InvalidOperationException("custody_disabled");
        if (request.ExpiresAt <= Now || request.ExpiresAt > Now + 120 || request.Operation is not ("list" or "cancel" or "purchase"))
            throw new FormatException("invalid_custody_request");
        OwnerSignature.Hex(request.Reference, 32); OwnerSignature.Hex(request.ConfigHash, 32); OwnerSignature.Hex(request.Nonce, 32);
        OwnerSignature.RequireEncryptionKey(request.EncryptionKey);
        if (!OwnerSignature.IsOwner(request.OwnerKey) || !OwnerSignature.Verify(Convert.ToHexStringLower(RequestHash(request, marketplace.Value)), request.OwnerKey, request.Signature))
            throw new InvalidOperationException("owner_authentication_failed");
        lock (gate)
        {
            if (stopping) throw new InvalidOperationException("custody_busy");
            Sweep();
            if (Duplicate(request) is { } duplicate) return duplicate.Handshake;
        }
        var receipt = journal.Find(request);
        using var work = await resources.Work.EnterAsync(receipt != null || request.Operation == "cancel", cancellationToken);
        var context = receipt?.Context ?? await directory.GetAsync(request.Operation, request.Reference, request.ConfigHash, cancellationToken);
        CustodyTrade.ReadPolicy(context, request, keys, marketplace.Value);
        lock (gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (stopping) throw new InvalidOperationException("custody_busy");
            if (request.ExpiresAt <= Now) throw new InvalidOperationException("custody_request_expired");
            Sweep();
            if (Duplicate(request) is { } duplicate) return duplicate.Handshake;
            receipt = journal.Find(request);
            if (receipt == null)
            {
                var active = sessions.Values.Where(s => !s.Completed).ToArray();
                var cancel = request.Operation == "cancel";
                if (active.Length >= custody.Value.MaximumSessions + (cancel ? custody.Value.ParallelTrades : 0) ||
                    (cancel ? active.Count(s => s.Request.Operation == "cancel") >= custody.Value.ParallelTrades ||
                        active.Any(s => s.Request.Operation == "cancel" && s.Request.OwnerKey == request.OwnerKey)
                    : active.Count(s => s.Request.OwnerKey == request.OwnerKey) >= custody.Value.MaximumSessionsPerOwner))
                    throw new InvalidOperationException("custody_busy");
            }
            if (sessions.Count >= custody.Value.MaximumRetainedSessions)
                foreach (var old in sessions.Values.Where(s => s.Completed).OrderBy(s => s.Handshake.ExpiresAt).ToArray())
                { Retire(old); if (sessions.Count < custody.Value.MaximumRetainedSessions) break; }
            if (sessions.Count >= custody.Value.MaximumRetainedSessions) throw new InvalidOperationException("custody_busy");
            var session = new Session(request, context, keys, marketplace.Value, custody.Value, Now) { RecoveryOnly = receipt != null };
            session.Trade = new(request, context, keys, proofs, directory, node, signers, journal, marketplace.Value, custody.Value, resources);
            sessions.Add(session.Handshake.SessionId, session);
            return session.Handshake;
        }
    }
    private Session? Duplicate(CustodyOpen request)
    {
        var duplicate = sessions.Values.FirstOrDefault(s => s.Request.OwnerKey == request.OwnerKey && s.Request.Nonce == request.Nonce);
        if (duplicate != null && duplicate.Request != request) throw new InvalidOperationException("nonce_reused");
        return duplicate;
    }
    private void RequireLive(Session session)
    {
        if (stopping || session.Revoked || session.Handshake.ExpiresAt <= Now ||
            !sessions.TryGetValue(session.Handshake.SessionId, out var actual) || !ReferenceEquals(actual, session))
            throw new InvalidOperationException("custody_session_expired");
    }
    public async Task<CustodyEnvelope> ExchangeAsync(string id, CustodyEnvelope envelope, CancellationToken cancellationToken)
    {
        OwnerSignature.Hex(id, 32);
        Session session;
        lock (gate) if (!sessions.TryGetValue(id, out session!)) throw new InvalidOperationException("custody_session_expired");
        if (!await session.Processing.WaitAsync(0, cancellationToken)) throw new CustodyCapacityException();
        try
        {
            lock (gate) RequireLive(session);
            if (envelope.Sequence == session.Sequence - 1 && session.LastRequest == envelope.Ciphertext && session.LastResponse != null)
                return session.LastResponse;
            if (envelope.Sequence != session.Sequence || envelope.Sequence is < 0 or > 15) throw new InvalidOperationException("invalid_sequence");
            var packet = session.Decrypt(envelope);
            if (packet.ValueKind != JsonValueKind.Object || !packet.TryGetProperty("type", out var packetType) || packetType.ValueKind != JsonValueKind.String)
                throw new FormatException("invalid_trade_packet");
            var type = packetType.GetString();
            var watch = Stopwatch.StartNew();
            long waitMs = 0;
            object result;
            try
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, shutdown.Token);
                deadline.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, session.Handshake.ExpiresAt - Now)));
                var token = deadline.Token;
                if (session.RecoveryOnly && type is not ("recover" or "close")) throw new InvalidOperationException("recovery_only_session");
                using (await resources.Items.EnterAsync(session.Reservation, token))
                lock (gate)
                {
                    RequireLive(session);
                    if (type is not ("recover" or "close"))
                    {
                        if (reservations.TryGetValue(session.Reservation, out var holder) && holder != id)
                        {
                            if (session.Request.Operation != "cancel") throw new InvalidOperationException("item_busy");
                            if (sessions.TryGetValue(holder, out var old)) { old.Revoked = true; Retire(old); }
                        }
                        reservations[session.Reservation] = id;
                    }
                }
                using (var admission = CancellationTokenSource.CreateLinkedTokenSource(token))
                {
                    admission.CancelAfter(TimeSpan.FromSeconds(2));
                    try { await session.Trade!.ReserveSignerAsync(type, admission.Token); }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested) { throw new CustodyCapacityException(); }
                }
                using var item = await resources.Items.EnterAsync(session.Reservation, token);
                lock (gate) RequireLive(session);
                if (type == "close") { session.Trade.Dispose(); result = new { type = "closed" }; }
                else
                {
                    using var work = await resources.Work.EnterAsync(type is "sign" or "recover" || session.Request.Operation == "cancel", token);
                    lock (gate) RequireLive(session);
                    waitMs = watch.ElapsedMilliseconds;
                    result = await session.Trade.ProcessAsync(packet, token);
                    if (type is "sign" or "recover")
                    {
                        if (journal.Find(session.Request) is { } receipt)
                        {
                            settlement.Notify(receipt.KeyImage);
                        }
                    }
                }
                logger.LogInformation("Custody {Operation} stage {Stage}: wait {WaitMs} ms, processing {ProcessingMs} ms, total {ElapsedMs} ms",
                    session.Request.Operation, type, waitMs, watch.ElapsedMilliseconds - waitMs, watch.ElapsedMilliseconds);
            }
            catch (Exception exception) when (exception is FormatException or InvalidOperationException or InvalidDataException or
                CryptographicException or HttpRequestException or JsonException or KeyNotFoundException or OverflowException or OperationCanceledException or IOException)
            {
                session.Trade!.Dispose();
                var reason = exception.Message.Length <= 80 && exception.Message.All(c => c is >= 'a' and <= 'z' or '_')
                    ? exception.Message : exception.GetType().Name;
                logger.LogWarning("Custody {Operation} stage {Stage} rejected after {ElapsedMs} ms: {Reason}", session.Request.Operation, type, watch.ElapsedMilliseconds, reason);
                result = new { type = "error", code = reason is "item_busy" or "indexer_syncing" or "custody_busy" ? reason : "trade_rejected" };
            }
            lock (gate) if (session.Completed && reservations.GetValueOrDefault(session.Reservation) == id) reservations.Remove(session.Reservation);
            var response = session.Encrypt(result, envelope.Sequence);
            session.Sequence++; session.LastRequest = envelope.Ciphertext; session.LastResponse = response;
            return response;
        }
        finally
        {
            session.Processing.Release();
            lock (gate) if (stopping || session.Revoked || session.Handshake.ExpiresAt <= Now) Retire(session);
        }
    }

    private void Retire(Session session)
    {
        if (!session.Processing.Wait(0)) return;
        try
        {
            sessions.Remove(session.Handshake.SessionId);
            if (reservations.GetValueOrDefault(session.Reservation) == session.Handshake.SessionId) reservations.Remove(session.Reservation);
            session.Dispose();
        }
        finally { session.Processing.Release(); }
    }
    private void Sweep()
    {
        foreach (var session in sessions.Values.Where(s => s.Revoked || s.Handshake.ExpiresAt <= Now).ToArray()) Retire(session);
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5), clock);
        var ticks = 0;
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                int active, retained;
                lock (gate) { Sweep(); active = sessions.Values.Count(s => !s.Completed); retained = sessions.Count; }
                if (++ticks % 6 == 0)
                {
                    var work = resources.Work.Snapshot(); var processes = resources.Signers.Snapshot();
                    logger.LogInformation("Custody capacity: sessions {Active}/{Retained}, workers {Workers}, work waiting {Waiting}, signers {Signers}, signer waiting {SignerWaiting}",
                        active, retained, work.Active, work.Waiting, processes.Active, processes.Waiting);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
    public override void Dispose()
    {
        StopSessions();
        base.Dispose();
    }
    private void StopSessions()
    {
        lock (gate) stopping = true;
        shutdown.Cancel();
        lock (gate) foreach (var session in sessions.Values.ToArray()) Retire(session);
    }
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        StopSessions();
        await base.StopAsync(cancellationToken);
    }
    private sealed class Session : IDisposable
    {
        public SemaphoreSlim Processing { get; } = new(1, 1);
        public bool Revoked { get; set; }
        public bool RecoveryOnly { get; init; }
        public bool Completed => Revoked || RecoveryOnly || Trade?.Completed == true;
        public CustodyOpen Request { get; }
        public CustodyHandshake Handshake { get; }
        public string Reservation { get; }
        public CustodyTrade? Trade { get; set; }
        public long Sequence { get; set; }
        public string? LastRequest { get; set; }
        public CustodyEnvelope? LastResponse { get; set; }
        private readonly byte[] readKey;
        private readonly byte[] writeKey;
        private readonly byte[] context;

        public Session(CustodyOpen request, CustodyContext state, CustodyKeys keys, MarketplaceOptions market, CustodyOptions options, long now)
        {
            Request = request;
            Reservation = state.Item?.Output.KeyImage ?? state.Listing!.Output.KeyImage;
            using var encryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var point = encryption.ExportParameters(false).Q;
            var publicKey = Convert.ToHexStringLower([4, .. point.X!, .. point.Y!]);
            var id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            var expiry = now + options.SessionMinutes * 60;
            context = MoneroProofCrypto.Hash(JsonSerializer.SerializeToUtf8Bytes(new { domain = "XTOP:CUSTODY:CHANNEL:V1",
                requestHash = Convert.ToHexStringLower(RequestHash(request, market)), sessionId = id, expiresAt = expiry,
                encryptionKey = publicKey, serviceOwnerKey = Convert.ToHexStringLower(keys.Owner) }, Json));
            var remoteBytes = OwnerSignature.Hex(request.EncryptionKey, 65);
            using var remote = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = remoteBytes[1..33], Y = remoteBytes[33..65] } });
            var shared = encryption.DeriveRawSecretAgreement(remote.PublicKey);
            var expanded = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 64, context, "XTOP:CUSTODY:CHANNEL:V1"u8.ToArray());
            readKey = expanded[..32]; writeKey = expanded[32..];
            CryptographicOperations.ZeroMemory(shared); CryptographicOperations.ZeroMemory(expanded);
            Handshake = new(id, expiry, Convert.ToHexStringLower(keys.Owner), publicKey,
                Convert.ToHexStringLower(context), Convert.ToHexStringLower(keys.Sign(context)));
        }
        private static byte[] Nonce(long sequence, bool response)
        {
            var nonce = new byte[12]; nonce[0] = response ? (byte)1 : (byte)0;
            BinaryPrimitives.WriteInt64BigEndian(nonce.AsSpan(4), sequence); return nonce;
        }
        public JsonElement Decrypt(CustodyEnvelope envelope)
        {
            if (envelope.Ciphertext.Length > 350000) throw new FormatException("message_too_large");
            var bytes = Convert.FromBase64String(envelope.Ciphertext);
            if (bytes.Length < 16) throw new FormatException("invalid_ciphertext");
            var plain = new byte[bytes.Length - 16];
            try
            {
                var nonce = Nonce(envelope.Sequence, false);
                using var aes = new AesGcm(readKey, 16);
                aes.Decrypt(nonce, bytes.AsSpan(0, plain.Length), bytes.AsSpan(plain.Length), plain, [.. context, .. nonce]);
                using var document = JsonDocument.Parse(plain);
                return document.RootElement.Clone();
            }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        public CustodyEnvelope Encrypt(object packet, long sequence)
        {
            var plain = JsonSerializer.SerializeToUtf8Bytes(packet, Json);
            try
            {
                var bytes = new byte[plain.Length + 16]; var nonce = Nonce(sequence, true);
                using var aes = new AesGcm(writeKey, 16);
                aes.Encrypt(nonce, plain, bytes.AsSpan(0, plain.Length), bytes.AsSpan(plain.Length), [.. context, .. nonce]);
                return new(sequence, Convert.ToBase64String(bytes));
            }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        public void Dispose() { Trade?.Dispose(); CryptographicOperations.ZeroMemory(readKey); CryptographicOperations.ZeroMemory(writeKey); }
    }
}
