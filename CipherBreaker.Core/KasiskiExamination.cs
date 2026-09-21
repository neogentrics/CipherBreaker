/// <summary>
/// Estimates a Vigenere key's length from repeated sequences in the ciphertext.
///
/// History:
/// Independently discovered by Charles Babbage around 1854 (never published; found only in his
/// papers after his death) and published by Friedrich Kasiski in 1863, whose name the technique
/// carries. Kasiski's examination was the first genuine break in the "indecipherable cipher" —
/// three centuries after Vigenere-family ciphers entered use, this was the technique that finally
/// showed their apparent strength rested entirely on the key length staying unknown.
///
/// Purpose:
/// If the same short plaintext sequence happens to line up with the same portion of the repeating
/// key twice, it encrypts to the SAME ciphertext sequence both times. The distance between two
/// such repeats must then be a multiple of the key length, since that is precisely the condition
/// under which the key realigns with itself. A single repeat only narrows the key length to one of
/// its distance's divisors; many repeats, tallied together, usually agree strongly on one — the
/// true key length is a factor of nearly every observed distance, while other numbers are factors
/// of only a few by coincidence.
///
/// This narrows the search rather than settling it outright, which is why
/// <see cref="VigenereSolver"/> treats it as a shortlist of candidates to test, cross-checked
/// against <see cref="FrequencyAnalysis.IndexOfCoincidence"/>, rather than a final answer on its
/// own. One reason it can't stand alone: every distance divisible by the true key length L is
/// automatically also divisible by every divisor of L, so a small divisor (2 or 3, for a true
/// length of 6) structurally accumulates AT LEAST as many votes as L itself, and often wins the
/// raw count outright. The real signature of a true length of 6 is not "6 wins" but "2, 3 and 6 -
/// its own divisor lattice - cluster together at the top with similar high vote counts, then the
/// count drops sharply for anything else." A human analyst reads that cluster; this class reports
/// the ranked votes and leaves picking the length among a cluster's members to the caller.
/// </summary>
public static class KasiskiExamination
{
    public readonly record struct LengthVote(int KeyLength, int Votes);

    /// <summary>
    /// Every distance between two occurrences of the same length-<paramref name="sequenceLength"/>
    /// substring. A sequence that occurs three or more times contributes a distance for every
    /// pair of its occurrences, since the key repeats between any two of them too.
    /// </summary>
    public static IReadOnlyList<int> FindRepeatDistances(string cipherText, int sequenceLength = 3)
    {
        string letters = FrequencyAnalysis.LettersOnly(cipherText);
        Dictionary<string, List<int>> positions = new();

        for (int i = 0; i + sequenceLength <= letters.Length; i++)
        {
            string sequence = letters.Substring(i, sequenceLength);
            if (!positions.TryGetValue(sequence, out var list))
            {
                list = new List<int>();
                positions[sequence] = list;
            }
            list.Add(i);
        }

        List<int> distances = new();
        foreach (var occurrences in positions.Values)
        {
            if (occurrences.Count < 2) continue;

            for (int i = 0; i < occurrences.Count; i++)
            {
                for (int j = i + 1; j < occurrences.Count; j++)
                {
                    distances.Add(occurrences[j] - occurrences[i]);
                }
            }
        }

        return distances;
    }

    /// <summary>
    /// Candidate key lengths ranked by how many observed repeat-distances they evenly divide —
    /// the standard Kasiski vote. Length 1 is excluded: it divides every distance trivially and
    /// carries no information about a repeating key.
    /// </summary>
    public static IReadOnlyList<LengthVote> EstimateKeyLength(
        string cipherText, int sequenceLength = 3, int maxKeyLength = 20)
    {
        var distances = FindRepeatDistances(cipherText, sequenceLength);
        int[] votes = new int[maxKeyLength + 1];

        foreach (int distance in distances)
        {
            for (int length = 2; length <= maxKeyLength; length++)
            {
                if (distance % length == 0) votes[length]++;
            }
        }

        return Enumerable.Range(2, maxKeyLength - 1)
            .Select(length => new LengthVote(length, votes[length]))
            .OrderByDescending(v => v.Votes)
            .ToList();
    }
}
