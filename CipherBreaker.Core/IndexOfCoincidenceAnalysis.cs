/// <summary>
/// Estimates a Vigenere key's length from how splitting the ciphertext into columns affects its
/// Index of Coincidence.
///
/// History:
/// Developed by William Friedman in 1922 at the US Army's Riverbank Laboratories, three decades
/// after Kasiski's method and independent of it. Friedman's insight applied statistics rather than
/// pattern-spotting: rather than needing a lucky repeated sequence, it measures a property of the
/// WHOLE ciphertext that responds predictably to the correct key length no matter what the message
/// happens to contain.
///
/// Purpose:
/// Splitting ciphertext into <paramref name="keyLength"/> interleaved columns groups together every
/// letter encrypted under the SAME single key letter — each column, on its own, is exactly a
/// Caesar-shifted fragment of English. A Caesar shift does not change a text's Index of
/// Coincidence (see <see cref="FrequencyAnalysis.IndexOfCoincidence"/>): it only relabels which
/// letter carries which frequency. So when the guessed length is correct, every column's IC sits
/// near English's own value, around 0.067. Guess the wrong length and the columns each mix several
/// different key letters' shifts together, which averages their distributions toward flat and
/// drags the IC down toward a random alphabet's 1/26 ≈ 0.0385.
///
/// Like <see cref="KasiskiExamination"/>, this narrows the search rather than settling it: it is
/// one of the two independent signals <see cref="VigenereSolver"/> cross-checks before actually
/// attacking each column.
/// </summary>
public static class IndexOfCoincidenceAnalysis
{
    public readonly record struct LengthEstimate(int KeyLength, double AverageIndexOfCoincidence);

    /// <summary>
    /// Splits <paramref name="text"/> into <paramref name="keyLength"/> columns (column i holds
    /// the letters at positions i, i + keyLength, i + 2*keyLength, ...) and returns each one.
    /// </summary>
    public static IReadOnlyList<string> SplitIntoColumns(string text, int keyLength)
    {
        string letters = FrequencyAnalysis.LettersOnly(text);
        var columns = new System.Text.StringBuilder[keyLength];
        for (int i = 0; i < keyLength; i++) columns[i] = new System.Text.StringBuilder();

        for (int i = 0; i < letters.Length; i++)
        {
            columns[i % keyLength].Append(letters[i]);
        }

        return columns.Select(c => c.ToString()).ToList();
    }

    /// <summary>The mean Index of Coincidence across all columns for a given candidate key length.</summary>
    public static double AverageIndexOfCoincidence(string text, int keyLength)
    {
        var columns = SplitIntoColumns(text, keyLength);
        var nonEmpty = columns.Where(c => c.Length >= 2).ToList();
        if (nonEmpty.Count == 0) return 0;

        return nonEmpty.Average(FrequencyAnalysis.IndexOfCoincidence);
    }

    /// <summary>
    /// Candidate key lengths from 1 to <paramref name="maxKeyLength"/>, ranked by average IC
    /// (highest first) — the length whose columns look most like ordinary English is the leading
    /// candidate. A genuine multiple of the true length also scores well (its columns are still
    /// each a single Caesar shift, just with less data each), which is why this is a ranked
    /// shortlist for <see cref="VigenereSolver"/> to test, not a single definitive answer.
    /// </summary>
    public static IReadOnlyList<LengthEstimate> EstimateKeyLength(string text, int maxKeyLength = 20)
    {
        return Enumerable.Range(1, maxKeyLength)
            .Select(length => new LengthEstimate(length, AverageIndexOfCoincidence(text, length)))
            .OrderByDescending(e => e.AverageIndexOfCoincidence)
            .ToList();
    }
}
