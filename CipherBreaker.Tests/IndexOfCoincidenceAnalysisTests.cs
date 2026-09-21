public class IndexOfCoincidenceAnalysisTests
{
    private const string HeldOutText =
        "TO SHERLOCK HOLMES SHE IS ALWAYS THE WOMAN I HAVE SELDOM HEARD HIM MENTION HER UNDER " +
        "ANY OTHER NAME IN HIS EYES SHE ECLIPSES AND PREDOMINATES THE WHOLE OF HER SEX IT WAS " +
        "NOT THAT HE FELT ANY EMOTION AKIN TO LOVE FOR IRENE ADLER ALL EMOTIONS AND THAT ONE " +
        "PARTICULARLY WERE ABHORRENT TO HIS COLD PRECISE BUT ADMIRABLY BALANCED MIND HE WAS I " +
        "TAKE IT THE MOST PERFECT REASONING AND OBSERVING MACHINE THAT THE WORLD HAS SEEN BUT " +
        "AS A LOVER HE WOULD HAVE PLACED HIMSELF IN A FALSE POSITION HE NEVER SPOKE OF THE " +
        "SOFTER PASSIONS SAVE WITH A GIBE AND A SNEER THEY WERE ADMIRABLE THINGS FOR THE " +
        "OBSERVER EXCELLENT FOR DRAWING THE VEIL FROM MEN S MOTIVES AND ACTIONS";

    [Fact]
    public void SplitIntoColumnsDistributesEveryLetterExactlyOnce()
    {
        string letters = FrequencyAnalysis.LettersOnly(HeldOutText);
        var columns = IndexOfCoincidenceAnalysis.SplitIntoColumns(HeldOutText, 5);

        Assert.Equal(5, columns.Count);
        Assert.Equal(letters.Length, columns.Sum(c => c.Length));
    }

    [Fact]
    public void ColumnZeroTakesEveryFifthLetterStartingAtZero()
    {
        string letters = FrequencyAnalysis.LettersOnly("ABCDEFGHIJ");
        var columns = IndexOfCoincidenceAnalysis.SplitIntoColumns(letters, 5);

        Assert.Equal("AF", columns[0]);
        Assert.Equal("BG", columns[1]);
    }

    /// <summary>
    /// The whole reason this class exists: for the correct key length, every column is a plain
    /// Caesar shift of English and its IC sits near English's own ~0.067. For a wrong length, the
    /// columns mix multiple shifts together and IC drops toward a random alphabet's ~0.0385.
    /// </summary>
    [Fact]
    public void CorrectKeyLengthScoresNotablyHigherThanAnUnrelatedWrongLength()
    {
        string cipherText = VigenereCipher.Encrypt(HeldOutText, "SECRET"); // length 6

        double correctLengthIC = IndexOfCoincidenceAnalysis.AverageIndexOfCoincidence(cipherText, 6);
        double wrongLengthIC = IndexOfCoincidenceAnalysis.AverageIndexOfCoincidence(cipherText, 11);

        Assert.True(correctLengthIC > wrongLengthIC,
            $"Expected length 6 ({correctLengthIC}) to score higher than length 11 ({wrongLengthIC})");
    }

    [Fact]
    public void TrueKeyLengthPlacesAmongTheTopCandidates()
    {
        string cipherText = VigenereCipher.Encrypt(HeldOutText, "SECRET");

        var ranked = IndexOfCoincidenceAnalysis.EstimateKeyLength(cipherText, maxKeyLength: 20);
        var topFive = ranked.Take(5).Select(e => e.KeyLength);

        Assert.Contains(6, topFive);
    }

    [Fact]
    public void EmptyColumnsDoNotCountTowardTheAverage() =>
        // Requesting more columns than there are letters must not throw or divide by zero.
        Assert.True(IndexOfCoincidenceAnalysis.AverageIndexOfCoincidence("AB", 50) >= 0);
}
