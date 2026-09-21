public class HillKnownPlaintextAttackTests
{
    /// <summary>
    /// Held-out test text: Arthur Conan Doyle's "A Scandal in Bohemia" - the same text used to
    /// test every other solver in this repo, for the same reason: it is not the corpus
    /// EnglishBigramModel was trained on, though this attack does not use that model at all -
    /// consistency with the other test suites matters more here than the bigram-independence
    /// itself.
    /// </summary>
    private const string HeldOutText =
        "TO SHERLOCK HOLMES SHE IS ALWAYS THE WOMAN I HAVE SELDOM HEARD HIM MENTION HER UNDER " +
        "ANY OTHER NAME IN HIS EYES SHE ECLIPSES AND PREDOMINATES THE WHOLE OF HER SEX IT WAS " +
        "NOT THAT HE FELT ANY EMOTION AKIN TO LOVE FOR IRENE ADLER ALL EMOTIONS AND THAT ONE " +
        "PARTICULARLY WERE ABHORRENT TO HIS COLD PRECISE BUT ADMIRABLY BALANCED MIND HE WAS I " +
        "TAKE IT THE MOST PERFECT REASONING AND OBSERVING MACHINE";

    /// <summary>
    /// The core claim of a known-plaintext attack: give it ciphertext and a crib whose CONTENT is
    /// known but whose POSITION is not, and it recovers the exact key. Unlike every other solver
    /// in this repo, this is exact linear algebra, not a statistical best guess - so the
    /// assertion is unconditional equality, not "close enough".
    /// </summary>
    [Fact]
    public void RecoversTheExactKeyFromACribOfUnknownPosition()
    {
        string cipherText = HillCipher.Encrypt(HeldOutText, "HILL");

        var result = HillKnownPlaintextAttack.Recover(cipherText, "SHERLOCK HOLMES");

        Assert.True(result.Success);
        Assert.Equal("HILL", result.Key);
        Assert.Equal(HillCipher.Decrypt(cipherText, "HILL"), result.Plaintext);
    }

    /// <summary>
    /// Regression test for a real bug found while verifying this attack: fixing the crib's FIRST
    /// digraph as one half of every trial pairing fails structurally, not just unluckily, when
    /// that digraph's own two letters are both even-valued - "EM" is E=4, M=12, so its column
    /// vector is even in every entry and forces an even determinant against ANY partner digraph.
    /// No amount of trying a different second digraph could ever have found a match; only trying
    /// a pairing that does not include "EM" at all works. This exact crib reproduces that failure
    /// if the fix regresses.
    /// </summary>
    [Fact]
    public void FindsAWorkingDigraphPairEvenWhenTheFirstDigraphIsStructurallyDegenerate()
    {
        string cipherText = HillCipher.Encrypt(HeldOutText, "RRLM");

        var result = HillKnownPlaintextAttack.Recover(cipherText, "EMOTIONS AND THAT");

        Assert.True(result.Success, result.Error);
        Assert.Equal("RRLM", result.Key);
        Assert.Equal(HillCipher.Decrypt(cipherText, "RRLM"), result.Plaintext);
    }

    /// <summary>The recovered offset must point at where the crib genuinely starts.</summary>
    [Fact]
    public void ReportsTheCorrectOffsetWhereTheCribWasFound()
    {
        string letters = FrequencyAnalysis.LettersOnly(HeldOutText);
        int expectedOffset = letters.IndexOf("SHERLOCKHOLMES", StringComparison.Ordinal);

        string cipherText = HillCipher.Encrypt(HeldOutText, "HILL");
        var result = HillKnownPlaintextAttack.Recover(cipherText, "SHERLOCK HOLMES");

        Assert.Equal(expectedOffset, result.PlaintextOffset);
    }

    /// <summary>A crib genuinely absent from the message must be reported as not found, not guessed at.</summary>
    [Fact]
    public void ReportsFailureWhenTheCribDoesNotAppearAnywhere()
    {
        string cipherText = HillCipher.Encrypt(HeldOutText, "HILL");

        var result = HillKnownPlaintextAttack.Recover(cipherText, "XYLOPHONEMUSICIAN");

        Assert.False(result.Success);
        Assert.Null(result.Key);
        Assert.NotNull(result.Error);
    }

    /// <summary>
    /// Honest, documented boundary: Hill encrypts fixed two-letter blocks from position 0, so
    /// this direct construction can only test even-offset alignments. "BALANCED MIND" genuinely
    /// appears in the held-out text, but at an odd letter offset, which this implementation
    /// cannot recover - and correctly reports as such rather than returning a wrong answer.
    /// </summary>
    [Fact]
    public void HonestlyFailsOnACribThatStartsAtAnOddOffset()
    {
        string letters = FrequencyAnalysis.LettersOnly(HeldOutText);
        int offset = letters.IndexOf("BALANCEDMIND", StringComparison.Ordinal);
        Assert.True(offset % 2 != 0, "This test's premise requires an odd offset; the fixture text changed.");

        string cipherText = HillCipher.Encrypt(HeldOutText, "HILL");
        var result = HillKnownPlaintextAttack.Recover(cipherText, "BALANCED MIND");

        Assert.False(result.Success);
    }

    [Fact]
    public void RejectsACribShorterThanTwoDigraphs()
    {
        string cipherText = HillCipher.Encrypt(HeldOutText, "HILL");

        var result = HillKnownPlaintextAttack.Recover(cipherText, "ABC");

        Assert.False(result.Success);
        Assert.Contains("4 letters", result.Error);
    }

    [Fact]
    public void RejectsACribWithNoInvertibleDigraphPairAtAll()
    {
        // Every digraph here pairs with every other to give an even determinant: all four
        // letters (A, C, E, M) are even-valued (0, 2, 4, 12), so every 2x2 built from them has
        // an even determinant and none can be inverted modulo 26.
        string cipherText = HillCipher.Encrypt(HeldOutText, "HILL");

        var result = HillKnownPlaintextAttack.Recover(cipherText, "ACEM");

        Assert.False(result.Success);
        Assert.Contains("inverse modulo 26", result.Error);
    }

    /// <summary>This is exact linear algebra, not a heuristic search: running it twice must
    /// always give the identical answer, with nothing probabilistic involved anywhere.</summary>
    [Fact]
    public void IsFullyDeterministic()
    {
        string cipherText = HillCipher.Encrypt(HeldOutText, "HILL");

        var first = HillKnownPlaintextAttack.Recover(cipherText, "SHERLOCK HOLMES");
        var second = HillKnownPlaintextAttack.Recover(cipherText, "SHERLOCK HOLMES");

        Assert.Equal(first, second);
    }
}
