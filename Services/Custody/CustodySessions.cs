using System.Buffers.Binary;
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
    IOptions<CustodyOptions> custody, TimeProvider clock, ILogger<CustodySessions> logger) : BackgroundService
{
    private readonly SemaphoreSlim gate = new(1);
    private readonly Dictionary<string, Session> sessions = [];
    private readonly Dictionary<string, string> reservations = [];
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static byte[] RequestHash(CustodyOpen request, MarketplaceOptions market) => MoneroProofCrypto.Hash(
        JsonSerializer.SerializeToUtf8Bytes(new { domain = "XTOP:CUSTODY:OPEN:V1", network = market.NetworkId, marketplace = market.Id,
            origin = market.PublicOrigin, request.Operation, request.Reference, request.ConfigHash, request.OwnerKey,
            request.EncryptionKey, request.Nonce, request.ExpiresAt }, Json));

    public async Task<CustodyHandshake> OpenAsync(CustodyOpen request, CancellationToken cancellationToken)
    {
        if (!keys.Enabled) throw new InvalidOperationException("custody_disabled");
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        if (request.ExpiresAt <= now || request.ExpiresAt > now + 120 || request.Operation is not ("list" or "cancel" or "purchase"))
            throw new FormatException("invalid_custody_request");
        OwnerSignature.Hex(request.Reference, 32); OwnerSignature.Hex(request.ConfigHash, 32); OwnerSignature.Hex(request.Nonce, 32);
        OwnerSignature.RequireEncryptionKey(request.EncryptionKey);
        if (!OwnerSignature.IsOwner(request.OwnerKey) || !OwnerSignature.Verify(Convert.ToHexStringLower(RequestHash(request, marketplace.Value)), request.OwnerKey, request.Signature))
            throw new InvalidOperationException("owner_authentication_failed");
        await gate.WaitAsync(cancellationToken);
        try
        {
            Sweep();
            var duplicate = sessions.Values.FirstOrDefault(s => s.Request.OwnerKey == request.OwnerKey && s.Request.Nonce == request.Nonce);
            if (duplicate != null)
            {
                if (duplicate.Request != request) throw new InvalidOperationException("nonce_reused");
                return duplicate.Handshake;
            }
            if (sessions.Count >= custody.Value.MaximumSessions) throw new InvalidOperationException("custody_busy");
            var context = await directory.GetAsync(request.Operation, request.Reference, request.ConfigHash, cancellationToken);
            CustodyTrade.ReadPolicy(context, request, keys, marketplace.Value);
            var session = new Session(request, context, keys, marketplace.Value, custody.Value, now);
            session.Trade = new(request, context, keys, proofs, directory, node, signers, journal, marketplace.Value, custody.Value);
            sessions.Add(session.Handshake.SessionId, session);
            return session.Handshake;
        }
        finally { gate.Release(); }
    }

    public async Task<CustodyEnvelope> ExchangeAsync(string id, CustodyEnvelope envelope, CancellationToken cancellationToken)
    {
        OwnerSignature.Hex(id, 32);
        await gate.WaitAsync(cancellationToken);
        try
        {
            Sweep();
            if (!sessions.TryGetValue(id, out var session)) throw new InvalidOperationException("custody_session_expired");
            if (envelope.Sequence == session.Sequence - 1 && session.LastRequest == envelope.Ciphertext && session.LastResponse != null)
                return session.LastResponse;
            if (envelope.Sequence != session.Sequence || envelope.Sequence is < 0 or > 15) throw new InvalidOperationException("invalid_sequence");
            var packet = session.Decrypt(envelope);
            if (packet.ValueKind != JsonValueKind.Object || !packet.TryGetProperty("type", out var packetType) || packetType.ValueKind != JsonValueKind.String)
                throw new FormatException("invalid_trade_packet");
            var recovery = packetType.GetString() == "recover";
            if (!recovery)
            {
                if (reservations.TryGetValue(session.Reservation, out var holder) && holder != id)
                {
                    if (session.Request.Operation != "cancel") throw new InvalidOperationException("item_busy");
                    if (sessions.Remove(holder, out var previous)) previous.Dispose();
                }
                reservations[session.Reservation] = id;
            }
            object result;
            try
            {
                result = await session.Trade!.ProcessAsync(packet, cancellationToken);
            }
            catch (Exception exception) when (exception is FormatException or InvalidOperationException or InvalidDataException or
                CryptographicException or HttpRequestException or JsonException or KeyNotFoundException or OverflowException or TaskCanceledException)
            {
                session.Trade!.Dispose();
                if (reservations.GetValueOrDefault(session.Reservation) == id) reservations.Remove(session.Reservation);
                var reason = exception.Message.All(c => c is >= 'a' and <= 'z' or '_') && exception.Message.Length <= 80
                    ? exception.Message : exception.GetType().Name;
                logger.LogWarning("Custody {Operation} rejected: {Reason}", session.Request.Operation, reason);
                result = new { type = "error", code = "trade_rejected" };
            }
            var response = session.Encrypt(result, envelope.Sequence);
            session.Sequence++;
            session.LastRequest = envelope.Ciphertext; session.LastResponse = response;
            return response;
        }
        finally { gate.Release(); }
    }

    private void Sweep()
    {
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        foreach (var session in sessions.Values.Where(s => s.Handshake.ExpiresAt <= now).ToArray())
        {
            sessions.Remove(session.Handshake.SessionId);
            if (reservations.GetValueOrDefault(session.Reservation) == session.Handshake.SessionId) reservations.Remove(session.Reservation);
            session.Dispose();
        }
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15), clock);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await gate.WaitAsync(stoppingToken);
                try { Sweep(); } finally { gate.Release(); }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
    public override void Dispose()
    {
        base.Dispose();
        foreach (var session in sessions.Values) session.Dispose();
    }

    private sealed class Session : IDisposable
    {
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
