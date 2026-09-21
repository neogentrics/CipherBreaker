using System.Text;

/// <summary>
/// Breaks a simple (monoalphabetic) substitution cipher with no known key, via hill-climbing.
///
/// History:
/// Simple substitution has 26! possible keys - roughly 4*10^26, far beyond exhaustive search.
/// For centuries the only attack was manual frequency analysis: a human matching common letters
/// and words by eye, which is slow and requires skill. Hill-climbing automates the same instinct
/// with a language model standing in for the human's sense of "does this look like English yet",
/// and is the standard modern technique for this exact problem (the approach popularised by tools
/// such as quipqiup, and described in the cryptanalysis literature as key-based local search).
///
/// Purpose:
/// Start from a random guess at the 26-letter key. Repeatedly try swapping two letters in it; if
/// the swap makes the decrypted text score higher against <see cref="EnglishBigramModel"/>, keep
/// it, otherwise undo it. This is a local search, so a single run can get stuck on a key that is
/// better than every neighbour it tried but still wrong overall (a local optimum). The fix used
/// here is the standard one: run the whole climb many times from different random starting keys
/// and keep the best-scoring result across all of them, since a wrong local optimum is very
/// unlikely to recur across many independent random starts.
///
/// This is genuinely probabilistic, not guaranteed, cryptanalysis: given enough ciphertext (a few
/// hundred letters is comfortable) and enough restarts, it recovers the exact key with high
/// probability, but a short message or an unlucky run can converge on a close-but-imperfect key.
/// That honesty is itself the point of a cryptanalysis tool - CryptoPortfolio's own ciphers always
/// succeed by construction, because they are given the key; this attacks a keyspace too large to
/// guarantee anything.
/// </summary>
public static class SimpleSubstitutionSolver
{
    public readonly record struct Result(string Key, string Plaintext, double Score);

    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /// <summary>
    /// Attempts to recover the plaintext and key with no key given.
    /// </summary>
    /// <param name="cipherText">Ciphertext to attack.</param>
    /// <param name="restarts">Independent random-start hill climbs to run, keeping the best.
    /// More restarts cost more time but escape more local optima.</param>
    /// <param name="seed">Fixes the random sequence for reproducible results (tests, demos).
    /// Omit for a genuinely random attempt.</param>
    public static Result Solve(string cipherText, int restarts = 30, int? seed = null)
    {
        Random random = seed.HasValue ? new Random(seed.Value) : new Random();

        char[]? bestKey = null;
        double bestScore = double.NegativeInfinity;

        for (int attempt = 0; attempt < restarts; attempt++)
        {
            char[] key = Alphabet.ToCharArray();
            Shuffle(key, random);

            double score = HillClimb(cipherText, key);

            if (score > bestScore)
            {
                bestScore = score;
                bestKey = (char[])key.Clone();
            }
        }

        string keyString = new(bestKey!);
        return new Result(keyString, Decrypt(cipherText, bestKey!), bestScore);
    }

    /// <summary>
    /// Climbs from the given starting key by repeatedly trying every possible pairwise swap and
    /// keeping any that improves the score, until a full pass finds no improvement at all (a
    /// local optimum for this starting point). Mutates <paramref name="key"/> in place and
    /// returns its final score.
    /// </summary>
    private static double HillClimb(string cipherText, char[] key)
    {
        double currentScore = EnglishBigramModel.Score(Decrypt(cipherText, key));

        bool improved = true;
        while (improved)
        {
            improved = false;

            for (int i = 0; i < 25; i++)
            {
                for (int j = i + 1; j < 26; j++)
                {
                    (key[i], key[j]) = (key[j], key[i]);
                    double candidateScore = EnglishBigramModel.Score(Decrypt(cipherText, key));

                    if (candidateScore > currentScore)
                    {
                        currentScore = candidateScore;
                        improved = true;
                    }
                    else
                    {
                        (key[i], key[j]) = (key[j], key[i]); // revert: this swap did not help
                    }
                }
            }
        }

        return currentScore;
    }

    /// <summary>
    /// Decrypts using a raw 26-letter key: key[i] is the plaintext letter that ciphertext letter
    /// ('A' + i) stands for. Unlike CryptoPortfolio's own SimpleSubstitutionCipher, which only
    /// reaches the subset of alphabets a single keyword can generate, this accepts ANY of the 26!
    /// permutations, because a general attack cannot assume the key it is looking for came from a
    /// keyword at all.
    /// </summary>
    private static string Decrypt(string cipherText, char[] key)
    {
        StringBuilder result = new();

        foreach (char c in cipherText ?? "")
        {
            char upper = char.ToUpperInvariant(c);
            if (upper is >= 'A' and <= 'Z')
            {
                char decrypted = key[upper - 'A'];
                result.Append(char.IsUpper(c) ? decrypted : char.ToLowerInvariant(decrypted));
            }
            else
            {
                result.Append(c);
            }
        }

        return result.ToString();
    }

    private static void Shuffle(char[] items, Random random)
    {
        for (int i = items.Length - 1; i > 0; i--)
        {
            int j = random.Next(i + 1);
            (items[i], items[j]) = (items[j], items[i]);
        }
    }
}
