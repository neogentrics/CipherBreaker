/// <summary>
/// Breaks the Caesar cipher with no known key.
///
/// History:
/// Caesar's cipher has only 25 possible shifts, which makes it the natural first target for
/// automated cryptanalysis: small enough to try every key by brute force, but real enough that
/// the scoring problem it poses — "which of 25 gibberish-looking outputs is actually English?" —
/// is exactly the problem every more advanced attack in this library also has to solve.
///
/// Purpose:
/// Every shift is tried. Each candidate plaintext is scored with
/// <see cref="FrequencyAnalysis.ChiSquared"/> against standard English letter frequencies; the
/// lowest score wins. This is a genuine attack, not a lookup: nothing here is told the key, and
/// the same technique — brute force over a small keyspace, English-likeness as the tiebreaker —
/// is the backbone of the Affine and Gronsfeld solvers too, wherever the keyspace stays small
/// enough to search exhaustively.
/// </summary>
public static class CaesarSolver
{
    public readonly record struct Candidate(int Shift, string Plaintext, double Score);

    /// <summary>
    /// Every possible shift, ranked best (lowest chi-squared score, most English-like) first.
    /// Returning the full ranking rather than just the winner lets a caller see how confident
    /// the guess is — a clear winner has a much lower score than the runner-up, while a short or
    /// unusual message may leave several shifts looking plausible.
    /// </summary>
    public static IReadOnlyList<Candidate> RankAllShifts(string cipherText)
    {
        var candidates = new List<Candidate>(26);

        for (int shift = 0; shift < 26; shift++)
        {
            string plaintext = CaesarCipher.Decrypt(cipherText, shift);
            double score = FrequencyAnalysis.ChiSquared(plaintext);
            candidates.Add(new Candidate(shift, plaintext, score));
        }

        return candidates.OrderBy(c => c.Score).ToList();
    }

    /// <summary>The single best-scoring shift and its decryption.</summary>
    public static Candidate Solve(string cipherText) => RankAllShifts(cipherText)[0];
}
