public class FrequencyAnalysisTests
{
    // A long, ordinary passage of natural English prose (the opening of the Gettysburg Address,
    // public domain) — long enough for frequency statistics to be meaningful, and crucially NOT
    // a pangram: text deliberately written to touch every letter (e.g. "the quick brown fox...")
    // has an artificially flattened distribution and understates English's real skew toward a
    // handful of common letters, which threw off the Index of Coincidence reference test below
    // until this was swapped in.
    private const string EnglishProse =
        "FOUR SCORE AND SEVEN YEARS AGO OUR FATHERS BROUGHT FORTH ON THIS CONTINENT A NEW " +
        "NATION CONCEIVED IN LIBERTY AND DEDICATED TO THE PROPOSITION THAT ALL MEN ARE CREATED " +
        "EQUAL NOW WE ARE ENGAGED IN A GREAT CIVIL WAR TESTING WHETHER THAT NATION OR ANY NATION " +
        "SO CONCEIVED AND SO DEDICATED CAN LONG ENDURE WE ARE MET ON A GREAT BATTLEFIELD OF THAT " +
        "WAR WE HAVE COME TO DEDICATE A PORTION OF THAT FIELD AS A FINAL RESTING PLACE FOR THOSE " +
        "WHO HERE GAVE THEIR LIVES THAT THAT NATION MIGHT LIVE";

    [Fact]
    public void LettersOnlyStripsEverythingButAZ() =>
        Assert.Equal("ABC", FrequencyAnalysis.LettersOnly("a1b2c3!@# "));

    [Fact]
    public void CountsSumsToTheNumberOfLetters()
    {
        var counts = FrequencyAnalysis.Counts(EnglishProse);
        Assert.Equal(FrequencyAnalysis.LettersOnly(EnglishProse).Length, counts.Values.Sum());
    }

    [Fact]
    public void EnglishFrequencyTableSumsToApproximatelyOneHundredPercent()
    {
        // Published frequency tables are independently-rounded percentages, so they never sum
        // to exactly 100 - this just guards against a transcription error large enough to matter.
        double total = FrequencyAnalysis.EnglishFrequencies.Values.Sum();
        Assert.InRange(total, 99.5, 100.5);
    }

    /// <summary>
    /// The whole point of chi-squared: real English must score far lower (more English-like)
    /// than the same letters in an order frequency analysis cannot recognise. A monoalphabetic
    /// substitution changes WHICH letter carries a given frequency, not the character count, so
    /// this test uses Atbash - a real cipher already in the portfolio - as the scrambled case.
    /// </summary>
    [Fact]
    public void RealEnglishScoresFarLowerThanCipheredText()
    {
        string ciphered = AtbashCipher.Transform(EnglishProse);

        double englishScore = FrequencyAnalysis.ChiSquared(EnglishProse);
        double cipheredScore = FrequencyAnalysis.ChiSquared(ciphered);

        Assert.True(englishScore < cipheredScore,
            $"Expected English ({englishScore}) to score lower than ciphered text ({cipheredScore}).");
    }

    [Fact]
    public void ChiSquaredOfEmptyTextIsMaxValue() =>
        Assert.Equal(double.MaxValue, FrequencyAnalysis.ChiSquared(""));

    [Fact]
    public void IndexOfCoincidenceOfShortTextIsZero() =>
        Assert.Equal(0, FrequencyAnalysis.IndexOfCoincidence("A"));

    /// <summary>
    /// The reference values every IC-based attack in this library depends on: English prose sits
    /// near 0.067, while a uniformly random 26-letter alphabet sits near 1/26 ≈ 0.0385.
    /// </summary>
    [Fact]
    public void EnglishIndexOfCoincidenceIsNearTheKnownReferenceValue()
    {
        double ic = FrequencyAnalysis.IndexOfCoincidence(EnglishProse);
        Assert.InRange(ic, 0.055, 0.075);
    }

    /// <summary>
    /// Monoalphabetic substitution relabels which letter carries which frequency; it does not
    /// flatten the distribution. Atbash's IC should stay close to English's, not drift toward
    /// the random-text value of ~0.0385 - this is the property that makes IC useful for telling
    /// monoalphabetic ciphers apart from polyalphabetic ones without needing to break either.
    /// </summary>
    [Fact]
    public void MonoalphabeticSubstitutionPreservesIndexOfCoincidence()
    {
        double englishIC = FrequencyAnalysis.IndexOfCoincidence(EnglishProse);
        double atbashIC = FrequencyAnalysis.IndexOfCoincidence(AtbashCipher.Transform(EnglishProse));

        Assert.InRange(atbashIC, englishIC - 0.01, englishIC + 0.01);
    }
}
