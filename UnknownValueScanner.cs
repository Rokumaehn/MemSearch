namespace OmniHax;

internal enum UnknownComparison
{
    Less,
    Greater,
    Equal
}

/// <summary>
/// Unknown-value scans: the first pass snapshots every candidate value, and each
/// successive pass keeps only the addresses whose value changed as requested,
/// updating the snapshot as it goes.
/// </summary>
internal sealed class UnknownValueScanner
{
    private const int ChunkSize = 1024 * 1024;

    private readonly ProcessMemory _memory;
    private readonly bool _writableOnly;
    private readonly bool _aligned;
    private readonly int _size;
    private readonly List<Candidate> _candidates = new();

    public UnknownValueScanner(ProcessMemory memory, MemoryValueType valueType, bool writableOnly, bool aligned)
    {
        _memory = memory;
        ValueType = valueType;
        _size = MemoryValueTypeInfo.SizeOf(valueType);
        _writableOnly = writableOnly;
        _aligned = aligned;
    }

    public MemoryValueType ValueType { get; }
    public int Count => _candidates.Count;

    public Task SnapshotAsync(IProgress<ScanProgress>? progress, CancellationToken token) =>
        Task.Run(() => FirstScan(progress, token), token);

    public Task CompareAsync(UnknownComparison comparison, IProgress<ScanProgress>? progress, CancellationToken token) =>
        Task.Run(() => FilterScan(comparison, progress, token), token);

    public IEnumerable<ulong> Addresses(int max)
    {
        int count = 0;
        foreach (Candidate candidate in _candidates)
        {
            if (count >= max)
                yield break;

            count++;
            yield return candidate.Address;
        }
    }

    private void FirstScan(IProgress<ScanProgress>? progress, CancellationToken token)
    {
        _candidates.Clear();

        List<MemoryRegion> regions = _memory.EnumerateRegions(_writableOnly);
        var buffer = new byte[ChunkSize + _size];
        int step = _aligned ? _size : 1;
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
                int available = (int)Math.Min((long)primary + _size - 1, remaining);

                if (!_memory.ReadBytes(region.Base + position, buffer, available, out int read) || read < _size)
                    break;

                int scanCount = Math.Min(primary, read);
                int maxStart = scanCount - _size;
                for (int offset = 0; offset <= maxStart; offset += step)
                {
                    ulong address = region.Base + position + (ulong)offset;
                    if (_aligned && address % (ulong)_size != 0)
                        continue;

                    _candidates.Add(new Candidate(address, ReadRaw(buffer, offset)));
                }

                bytesScanned += primary;
                position += unchecked((ulong)primary);
            }

            progress?.Report(new ScanProgress(r + 1, regions.Count, bytesScanned, _candidates.Count));
        }
    }

    private void FilterScan(UnknownComparison comparison, IProgress<ScanProgress>? progress, CancellationToken token)
    {
        var buffer = new byte[_size];
        int total = _candidates.Count;
        int processed = 0;
        int write = 0;

        for (int i = 0; i < total; i++)
        {
            token.ThrowIfCancellationRequested();
            Candidate candidate = _candidates[i];

            if (_memory.ReadBytes(candidate.Address, buffer, _size, out int read) && read == _size)
            {
                ulong current = ReadRaw(buffer, 0);
                if (Matches(comparison, candidate.Value, current))
                    _candidates[write++] = new Candidate(candidate.Address, current);
            }

            processed++;
            if ((processed & 0x3FF) == 0)
                progress?.Report(new ScanProgress(processed, total, 0, write));
        }

        if (write < total)
            _candidates.RemoveRange(write, total - write);

        progress?.Report(new ScanProgress(total, total, 0, write));
    }

    private bool Matches(UnknownComparison comparison, ulong previous, ulong current)
    {
        int cmp = MemoryValueTypeInfo.Compare(ValueType, current, previous);
        return comparison switch
        {
            UnknownComparison.Less => cmp < 0,
            UnknownComparison.Greater => cmp > 0,
            _ => cmp == 0
        };
    }

    private ulong ReadRaw(byte[] buffer, int offset)
    {
        ulong value = 0;
        for (int i = 0; i < _size; i++)
            value |= (ulong)buffer[offset + i] << (8 * i);
        return value;
    }

    private readonly record struct Candidate(ulong Address, ulong Value);
}
