namespace OmniHax;

internal sealed record ScanProgress(long RegionsDone, long RegionsTotal, long BytesScanned, long Found);

/// <summary>
/// Performs exact-value scans against a process. The first scan walks all
/// committed regions; subsequent scans only re-check the surviving candidates,
/// narrowing the result set.
/// </summary>
internal sealed class MemoryScanner
{
    private const int ChunkSize = 1024 * 1024;

    private readonly ProcessMemory _memory;
    private readonly bool _writableOnly;
    private readonly bool _aligned;
    private readonly List<ulong> _candidates = new();

    public MemoryValueType ValueType { get; }
    public bool HasScanned { get; private set; }
    public IReadOnlyList<ulong> Candidates => _candidates;

    public MemoryScanner(ProcessMemory memory, MemoryValueType valueType, bool writableOnly, bool aligned)
    {
        _memory = memory;
        ValueType = valueType;
        _writableOnly = writableOnly;
        _aligned = aligned;
    }

    public void Reset()
    {
        _candidates.Clear();
        HasScanned = false;
    }

    public Task<IReadOnlyList<ulong>> ScanAsync(string searchText, IProgress<ScanProgress>? progress, CancellationToken token)
    {
        if (!MemoryValueTypeInfo.TryParse(ValueType, searchText, out byte[] pattern, out _, out string error))
            throw new FormatException(error);

        return Task.Run<IReadOnlyList<ulong>>(() =>
        {
            List<ulong> found = HasScanned
                ? FilterScan(pattern, progress, token)
                : FirstScan(pattern, progress, token);

            _candidates.Clear();
            _candidates.AddRange(found);
            HasScanned = true;
            return found;
        }, token);
    }

    private List<ulong> FirstScan(byte[] pattern, IProgress<ScanProgress>? progress, CancellationToken token)
    {
        var results = new List<ulong>();
        List<MemoryRegion> regions = _memory.EnumerateRegions(_writableOnly);
        var buffer = new byte[ChunkSize + 8];
        int size = pattern.Length;
        long bytesScanned = 0;

        for (int r = 0; r < regions.Count; r++)
        {
            token.ThrowIfCancellationRequested();
            MemoryRegion region = regions[r];
            ulong position = 0;

            while (position < region.Size)
            {
                token.ThrowIfCancellationRequested();

                long remaining = unchecked((long)(region.Size - position));
                int primary = (int)Math.Min(ChunkSize, remaining);
                int available = (int)Math.Min((long)primary + size - 1, remaining);

                if (!_memory.ReadBytes(region.Base + position, buffer, available, out int read) || read < size)
                    break;

                int scanCount = Math.Min(primary, read);
                CollectMatches(buffer.AsSpan(0, read), scanCount, pattern, region.Base + position, results,
                    _aligned ? size : 1);
                bytesScanned += primary;
                position += unchecked((ulong)primary);
            }

            progress?.Report(new ScanProgress(r + 1, regions.Count, bytesScanned, results.Count));
        }

        return results;
    }

    private List<ulong> FilterScan(byte[] pattern, IProgress<ScanProgress>? progress, CancellationToken token)
    {
        var survivors = new List<ulong>(_candidates.Count);
        var buffer = new byte[pattern.Length];
        int total = _candidates.Count;
        long processed = 0;

        foreach (ulong address in _candidates)
        {
            token.ThrowIfCancellationRequested();

            if (_memory.ReadBytes(address, buffer, buffer.Length, out int read) &&
                read == buffer.Length &&
                buffer.AsSpan().SequenceEqual(pattern))
            {
                survivors.Add(address);
            }

            processed++;
            if ((processed & 0x3FF) == 0)
                progress?.Report(new ScanProgress(processed, total, 0, survivors.Count));
        }

        progress?.Report(new ScanProgress(total, total, 0, survivors.Count));
        return survivors;
    }

    private static void CollectMatches(
        ReadOnlySpan<byte> buffer,
        int scanCount,
        byte[] pattern,
        ulong baseAddress,
        List<ulong> results,
        int align)
    {
        int size = pattern.Length;
        if (scanCount < size)
            return;

        ReadOnlySpan<byte> pat = pattern;
        int maxStart = scanCount - size;
        int start = 0;

        while (start <= maxStart)
        {
            ReadOnlySpan<byte> window = buffer.Slice(start, buffer.Length - start);
            int index = window.IndexOf(pat);
            if (index < 0)
                break;

            int matchPosition = start + index;
            if (matchPosition > maxStart)
                break;

            ulong address = baseAddress + unchecked((ulong)matchPosition);
            if (align <= 1 || address % (ulong)align == 0)
                results.Add(address);

            start = matchPosition + 1;
        }
    }
}
