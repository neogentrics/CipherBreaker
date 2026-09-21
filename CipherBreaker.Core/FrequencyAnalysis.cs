using System.Linq;
using System.Text;

/// <summary>
/// Letter-frequency statistics: the foundation every classical attack in this library builds on.
///
/// History:
/// Frequency analysis is the oldest cryptanalytic technique on record, described by the Arab
/// scholar Al-Kindi around 850 CE and rediscovered independently in Renaissance Europe. It is the
/// reason simple substitution ciphers, no matter how large their keyspace, were never actually
/// secure: scrambling the alphabet does not scramble how often each letter is used.
///
/// Purpose:
/// This class answers two different questions.
///
/// "Does this text read as English?" — <see cref="ChiSquared"/> compares a text's letter
/// frequencies against the known frequencies of English prose. A correctly decrypted message
/// scores low; a wrong guess looks like noise and scores high. This is the scoring function every
/// solver in this library uses to pick a winner out of many candidate decryptions, because a
/// computer cannot "recognise" English the way a person reading over the results can — it needs a
/// number to minimise.
///
/// "What KIND of cipher produced this?" — <see cref="IndexOfCoincidence"/> measures how unevenly
/// letters are distributed, which survives simple substitution (rearranging the alphabet does not
/// flatten its frequency profile) but is destroyed by polyalphabetic substitution (mixing several
/// shifted alphabets averages the profile toward flat). A high IC suggests monoalphabetic
/// substitution or transposition; a low IC suggests Vigenere or better. This is what lets an
/// attacker identify a cipher family before attempting to break it.
/// </summary>
public static class FrequencyAnalysis
{
    /// <summary>
    /// Standard published English letter frequencies (percent), A through Z.
    /// Source: the frequency table compiled from Concise Oxford Dictionary entries, the same
    /// reference table used throughout the cryptanalysis literature.
    /// </summary>
    public static readonly IReadOnlyDictionary<char, double> EnglishFrequencies = new Dictionary<char, double>
    {
        ['A'] = 8.167, ['B'] = 1.492, ['C'] = 2.782, ['D'] = 4.253, ['E'] = 12.702,
        ['F'] = 2.228, ['G'] = 2.015, ['H'] = 6.094, ['I'] = 6.966, ['J'] = 0.153,
        ['K'] = 0.772, ['L'] = 4.025, ['M'] = 2.406, ['N'] = 6.749, ['O'] = 7.507,
        ['P'] = 1.929, ['Q'] = 0.095, ['R'] = 5.987, ['S'] = 6.327, ['T'] = 9.056,
        ['U'] = 2.758, ['V'] = 0.978, ['W'] = 2.360, ['X'] = 0.150, ['Y'] = 1.974,
        ['Z'] = 0.074,
    };

    /// <summary>Strips a string down to uppercase A-Z, discarding everything a letter-frequency count can't use.</summary>
    public static string LettersOnly(string text)
    {
        StringBuilder result = new();
        foreach (char c in (text ?? "").ToUpperInvariant())
        {
            if (c is >= 'A' and <= 'Z') result.Append(c);
        }
        return result.ToString();
    }

    /// <summary>Raw counts of each letter A-Z in the text. Non-letters are ignored.</summary>
    public static Dictionary<char, int> Counts(string text)
    {
        Dictionary<char, int> counts = new();
        for (char c = 'A'; c <= 'Z'; c++) counts[c] = 0;

        foreach (char c in LettersOnly(text)) counts[c]++;

        return counts;
    }

    /// <summary>
    /// Pearson's chi-squared statistic comparing this text's letter distribution against
    /// standard English. Lower is more English-like; 0 would be a perfect match. This is the
    /// standard scoring function in classical cryptanalysis for picking the best of several
    /// candidate decryptions, precisely because "does this look like English" needs to become a
    /// number a program can minimise.
    ///
    /// Undefined (returns <see cref="double.MaxValue"/>) for empty input, so a solver comparing
    /// candidates never mistakes "no data" for "a perfect match".
    /// </summary>
    public static double ChiSquared(string text)
    {
        string letters = LettersOnly(text);
        if (letters.Length == 0) return double.MaxValue;

        var counts = Counts(letters);
        double n = letters.Length;
        double score = 0;

        foreach (var (letter, expectedPercent) in EnglishFrequencies)
        {
            double expected = expectedPercent / 100.0 * n;
            double observed = counts[letter];
            double diff = observed - expected;
            score += diff * diff / expected;
        }

        return score;
    }

    /// <summary>
    /// The Index of Coincidence: the probability that two letters drawn at random from the text
    /// are the same. Friedman's formula, sum(f_i * (f_i - 1)) over N * (N - 1).
    ///
    /// Reference points: English prose is around 0.067 (letters are used unevenly). A uniformly
    /// random 26-letter alphabet is 1/26 ≈ 0.0385. Simple substitution preserves English's
    /// unevenness (it just relabels which letter carries which frequency) and stays near 0.067.
    /// Polyalphabetic substitution like Vigenere averages several shifted alphabets together,
    /// flattening the distribution toward the random value — the more independent alphabets in
    /// use, the closer to 0.0385 the text reads. This is what makes IC useful for identifying a
    /// cipher family before attempting to break it, and for estimating a Vigenere key's length.
    ///
    /// Undefined (returns 0) for texts too short to have two letters to compare.
    /// </summary>
    public static double IndexOfCoincidence(string text)
    {
        string letters = LettersOnly(text);
        long n = letters.Length;
        if (n < 2) return 0;

        var counts = Counts(letters);
        double numerator = counts.Values.Sum(f => (double)f * (f - 1));
        double denominator = n * (n - 1);

        return numerator / denominator;
    }
}
