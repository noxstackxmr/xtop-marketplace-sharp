using System.Security.Cryptography;
using MarketplaceCore.Crypto;
using MarketplaceCore.Options;
using MarketplaceCore.Services.Indexer;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Services.Channels;

public sealed record AdmissionRequest(string Role, string ListingId, string OwnerKey, string Nonce, long ExpiresAt, string Signature);
public sealed record AdmissionGrant(string OwnerKey, string Role, string ListingId);
public sealed record AdmissionTicket(string Ticket, long ExpiresAt);

public sealed class RelayAdmission(IListingDirectory listings, RelayState state, IOptions<MarketplaceOptions> market, TimeProvider clock)
{
    public const string ContextKey = "null.relay.admission";
    private readonly object gate = new();
    private readonly Dictionary<string, Entry> entries = [];
    private long Now => clock.GetUtcNow().ToUnixTimeSeconds();
    public static string Hash(AdmissionRequest r, MarketplaceOptions m) => ChannelTranscript.Admission(m, r.Role, r.ListingId, r.OwnerKey, r.Nonce, r.ExpiresAt);
    public async Task<AdmissionTicket> Issue(AdmissionRequest request, CancellationToken token)
    {
        if (request.Role is not ("seller" or "buyer") || request.ExpiresAt <= Now || request.ExpiresAt > Now + 120 || !OwnerSignature.IsOwner(request.OwnerKey))
            throw new RelayException("invalid_admission");
        OwnerSignature.Hex(request.Nonce,32);
        if (request.Role == "buyer") OwnerSignature.Hex(request.ListingId,32);
        else if (request.ListingId != "") throw new RelayException("invalid_admission");
        var hash = Hash(request,market.Value);
        if (!OwnerSignature.Verify(hash,request.OwnerKey,request.Signature)) throw new RelayException("invalid_signature");
        lock(gate) { Sweep(); if (entries.TryGetValue(hash,out var found)) return Available(found); }
        if (request.Role == "seller")
        {
            if (await listings.SellerAsync(request.OwnerKey,token) == null) throw new RelayException("seller_listing_required");
        }
        else
        {
            var listing = await listings.GetAsync(request.ListingId,token);
            if (state.ListingUnavailable(listing) is {} reason) throw new RelayException(reason);
            if (listing!.SellerOwnerKey == request.OwnerKey) throw new RelayException("same_participant");
            if (!state.IsOnline(listing.SellerOwnerKey)) throw new RelayException("seller_offline");
        }
        lock(gate)
        {
            Sweep();
            if (request.ExpiresAt <= Now) throw new RelayException("admission_expired");
            if (entries.TryGetValue(hash,out var found)) return Available(found);
            if (entries.Count >= 2048 || entries.Values.Count(e=>e.Grant.OwnerKey==request.OwnerKey && !e.Consumed && e.Ticket.ExpiresAt>Now)>=4)
                throw new RelayException("admission_limit");
            var entry = new Entry(new(request.OwnerKey,request.Role,request.ListingId), new(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)), Math.Min(Now+30,request.ExpiresAt)), request.ExpiresAt);
            entries.Add(hash,entry);return entry.Ticket;
        }
    }
    public AdmissionGrant? Consume(string ticket)
    {
        if (ticket.Length != 64) return null;
        lock(gate)
        {
            Sweep();var entry=entries.Values.FirstOrDefault(e=>e.Ticket.Ticket==ticket);
            if (entry==null || entry.Consumed || entry.Ticket.ExpiresAt<=Now) return null;
            entry.Consumed=true;return entry.Grant;
        }
    }
    private AdmissionTicket Available(Entry entry) => !entry.Consumed && entry.Ticket.ExpiresAt>Now ? entry.Ticket : throw new RelayException("admission_expired");
    private void Sweep() { foreach(var key in entries.Where(e=>e.Value.RetainUntil<=Now).Select(e=>e.Key).ToArray()) entries.Remove(key); }
    private sealed class Entry(AdmissionGrant grant, AdmissionTicket ticket, long retainUntil)
    {
        public AdmissionGrant Grant {get;}=grant;
        public AdmissionTicket Ticket {get;}=ticket;
        public long RetainUntil {get;}=retainUntil;
        public bool Consumed {get;set;}
    }
}
