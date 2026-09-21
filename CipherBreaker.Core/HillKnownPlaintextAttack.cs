/// <summary>
/// Recovers a 2x2 Hill cipher key from a known- or guessed-plaintext crib, without needing to
/// know where in the ciphertext it appears.
///
/// History:
/// Lester Hill published his cipher in 1929 as a serious application of linear algebra to
/// cryptography, and it remains vulnerable to exactly the kind of attack its own mathematics
/// invites: if an analyst can match a handful of known plaintext letters to their ciphertext,
/// recovering the key is not a search at all, but solving a system of linear equations. This has
/// been a textbook weakness of Hill ciphers since not long after their introduction.
///
/// Purpose:
/// This is a genuinely different attack model from every other solver in this library. Caesar,
/// simple substitution and Vigenere are all CIPHERTEXT-ONLY attacks: nothing is assumed about the
/// plaintext beyond "it is ordinary English", and the answer is found by scoring candidates
/// statistically. A known-plaintext attack instead assumes the analyst has a CRIB — some fragment
/// of plaintext they know or strongly suspect appears in the message (a standard heading, a
/// guessed greeting, a repeated phrase from an earlier intercepted message) — and asks what the
/// key must have been for that to be true. Given two linearly independent plaintext digraphs and
/// their matching ciphertext digraphs, the 2x2 key matrix K is not merely likely, it is UNIQUELY
/// DETERMINED: C = K * P (mod 26) for plaintext matrix P and ciphertext matrix C, so
/// K = C * P^-1 (mod 26) whenever P has an inverse modulo 26. There is no statistics here and
/// nothing to hill-climb; a successful recovery is exact, not probable.
///
/// What is genuinely searched is the ALIGNMENT: Hill encrypts fixed, non-overlapping two-letter
/// blocks starting at position 0, so a crib can only line up cleanly with that block grid at an
/// EVEN offset into the ciphertext. This class tries every even offset, and for each one solves
/// for K and then verifies by decrypting the WHOLE ciphertext and checking that the result
/// actually contains the ENTIRE crib at that position — not just the four letters used to derive
/// the key. A coincidental match across a real crib of any useful length, at the wrong key and
/// the wrong offset, is astronomically unlikely, which is what makes that check trustworthy.
///
/// A crib known to start at an ODD offset is a real, documented limitation of this
/// implementation: unlike the block-aligned case, an odd offset means the crib's own letters do
/// not correspond to a clean sequence of whole ciphertext digraphs, and recovering a key from
/// that would need a different construction than the one here.
///
/// The two digraphs used to build the equation do not have to be the crib's first two: whenever a
/// pairing's matrix has no inverse modulo 26 (an unlucky but real possibility), the crib's first
/// digraph is paired with each later one in turn until an invertible combination is found, the
/// same way a human analyst would simply try a different pair of letters from a crib long enough
/// to offer one.
/// </summary>
public static class HillKnownPlaintextAttack
{
    public readonly record struct Result(
        bool Success, string? Key, string? Plaintext, int? PlaintextOffset, string? Error);

    /// <param name="cipherText">Ciphertext to attack.</param>
    /// <param name="knownPlaintext">A crib: plaintext believed to appear SOMEWHERE in the message.
    /// Its position does not need to be known - only its content. At least 4 letters (two
    /// digraphs) are required; a longer crib makes the alignment check more reliable and lets a
    /// wrong key's coincidental partial match be told apart from a genuine one.</param>
    public static Result Recover(string cipherText, string knownPlaintext)
    {
        string crib = FrequencyAnalysis.LettersOnly(knownPlaintext);
        string cipher = FrequencyAnalysis.LettersOnly(cipherText);

        if (crib.Length < 4)
        {
            return new Result(false, null, null, null,
                "Need at least 4 letters of known plaintext (two digraphs) to solve a 2x2 Hill key.");
        }

        int digraphCount = crib.Length / 2;
        bool triedAnyInvertiblePair = false;

        // Two linearly independent digraphs are all the maths needs - not specifically the
        // first two, and not even specifically a pair that includes the first. Fixing one
        // digraph and only varying the other can fail structurally rather than by bad luck: if
        // that fixed digraph's own two letters are both even-valued (as in "EM", E=4 and M=12),
        // its column vector is even in every entry, which forces the determinant of ANY pairing
        // built from it to be even too - so no partner digraph could ever rescue it. The only
        // fully general fix is to try every pair of digraphs in the crib, not just those sharing
        // one anchor, the same way a human analyst would simply pick two different letters from
        // a long enough crib until one pairing works.
        for (int first = 0; first < digraphCount - 1 && !triedAnyInvertiblePair; first++)
        for (int second = first + 1; second < digraphCount; second++)
        {
            int a = first * 2;
            int j = second * 2;
            int[,] plaintextMatrix =
            {
                { crib[a] - 'A', crib[j] - 'A' },
                { crib[a + 1] - 'A', crib[j + 1] - 'A' },
            };

            if (!TryInvertMatrixMod26(plaintextMatrix, out int[,] plaintextInverse)) continue;
            triedAnyInvertiblePair = true;

            for (int offset = 0; offset + crib.Length <= cipher.Length; offset += 2)
            {
                int[,] cipherMatrix =
                {
                    { cipher[offset + a] - 'A', cipher[offset + j] - 'A' },
                    { cipher[offset + a + 1] - 'A', cipher[offset + j + 1] - 'A' },
                };

                int[,] keyMatrix = MultiplyMod26(cipherMatrix, plaintextInverse);
                string key = MatrixToKeyString(keyMatrix);

                string plaintext = HillCipher.Decrypt(cipherText, key);
                string plaintextLetters = FrequencyAnalysis.LettersOnly(plaintext);

                bool cribConfirmed =
                    offset + crib.Length <= plaintextLetters.Length &&
                    plaintextLetters.Substring(offset, crib.Length) == crib;

                if (cribConfirmed)
                {
                    return new Result(true, key, plaintext, offset, null);
                }
            }
        }

        if (!triedAnyInvertiblePair)
        {
            return new Result(false, null, null, null,
                "No two digraphs in this crib form a matrix with an inverse modulo 26. Try a " +
                "different or longer crib.");
        }

        return new Result(false, null, null, null,
            "No even-offset alignment of the crib produced a consistent key. The crib may not " +
            "actually appear in this message, or may start at an odd offset, which this direct " +
            "block-aligned construction cannot recover.");
    }

    private static int Mod26(int value) => ((value % 26) + 26) % 26;

    private static int Gcd(int a, int b) => b == 0 ? a : Gcd(b, a % b);

    private static int ModInverse(int a)
    {
        a = Mod26(a);
        for (int x = 1; x < 26; x++)
        {
            if (a * x % 26 == 1) return x;
        }
        throw new InvalidOperationException($"{a} has no inverse modulo 26.");
    }

    private static bool TryInvertMatrixMod26(int[,] matrix, out int[,] inverse)
    {
        inverse = new int[2, 2];

        int determinant = Mod26(matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0]);
        if (Gcd(determinant, 26) != 1) return false;

        int determinantInverse = ModInverse(determinant);
        inverse[0, 0] = Mod26(matrix[1, 1] * determinantInverse);
        inverse[0, 1] = Mod26(-matrix[0, 1] * determinantInverse);
        inverse[1, 0] = Mod26(-matrix[1, 0] * determinantInverse);
        inverse[1, 1] = Mod26(matrix[0, 0] * determinantInverse);
        return true;
    }

    private static int[,] MultiplyMod26(int[,] a, int[,] b)
    {
        int[,] result = new int[2, 2];
        for (int i = 0; i < 2; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                int sum = 0;
                for (int k = 0; k < 2; k++) sum += a[i, k] * b[k, j];
                result[i, j] = Mod26(sum);
            }
        }
        return result;
    }

    /// <summary>
    /// Packs a matrix back into the 4-letter key string HillCipher itself expects: reading
    /// left-to-right, top-to-bottom, matching HillCipher.Encrypt's own key-parsing order exactly.
    /// </summary>
    private static string MatrixToKeyString(int[,] matrix) => new(new[]
    {
        (char)('A' + matrix[0, 0]), (char)('A' + matrix[0, 1]),
        (char)('A' + matrix[1, 0]), (char)('A' + matrix[1, 1]),
    });
}
