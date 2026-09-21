public class VigenereSolverTests
{
    /// <summary>
    /// Held-out test text: Arthur Conan Doyle's "A Scandal in Bohemia" - a different author from
    /// EnglishBigramModel's training corpus (Jane Austen), for the same reason every solver in
    /// this repo is tested on unseen prose: it measures generalisation, not memorisation.
    /// </summary>
    private const string HeldOutText =
        "TO SHERLOCK HOLMES SHE IS ALWAYS THE WOMAN I HAVE SELDOM HEARD HIM MENTION HER UNDER " +
        "ANY OTHER NAME IN HIS EYES SHE ECLIPSES AND PREDOMINATES THE WHOLE OF HER SEX IT WAS " +
        "NOT THAT HE FELT ANY EMOTION AKIN TO LOVE FOR IRENE ADLER ALL EMOTIONS AND THAT ONE " +
        "PARTICULARLY WERE ABHORRENT TO HIS COLD PRECISE BUT ADMIRABLY BALANCED MIND HE WAS I " +
        "TAKE IT THE MOST PERFECT REASONING AND OBSERVING MACHINE THAT THE WORLD HAS SEEN BUT " +
        "AS A LOVER HE WOULD HAVE PLACED HIMSELF IN A FALSE POSITION HE NEVER SPOKE OF THE " +
        "SOFTER PASSIONS SAVE WITH A GIBE AND A SNEER THEY WERE ADMIRABLE THINGS FOR THE " +
        "OBSERVER EXCELLENT FOR DRAWING THE VEIL FROM MEN S MOTIVES AND ACTIONS BUT FOR THE " +
        "TRAINED REASONER TO ADMIT SUCH INTRUSIONS INTO HIS OWN DELICATE AND FINELY ADJUSTED " +
        "TEMPERAMENT WAS TO INTRODUCE A DISTRACTING FACTOR WHICH MIGHT THROW A DOUBT UPON ALL " +
        "HIS MENTAL RESULTS GRIT IN A SENSITIVE INSTRUMENT OR A CRACK IN ONE OF HIS OWN HIGH " +
        "POWER LENSES WOULD NOT BE MORE DISTURBING THAN A STRONG EMOTION IN A NATURE SUCH AS " +
        "HIS AND YET THERE WAS BUT ONE WOMAN TO HIM AND THAT WOMAN WAS THE LATE IRENE ADLER OF " +
        "DUBIOUS AND QUESTIONABLE MEMORY";

    /// <summary>
    /// The real test: no key length, no key, nothing but ciphertext. This is what Kasiski and
    /// Friedman's own techniques achieved in 1863 and 1922 respectively against a cipher that had
    /// stood for three centuries as "indecipherable" - reusing the same two signals here, plus
    /// CaesarSolver (already proven independently) to attack whatever key length they agree on.
    /// </summary>
    [Theory]
    [InlineData("SECRET")]
    [InlineData("SHADOWY")]
    [InlineData("KEY")]
    [InlineData("MIDNIGHT")]
    [InlineData("LONGERKEYWORD")]
    public void RecoversTheExactKeyAndPlaintextWithNothingButCiphertext(string realKey)
    {
        string cipherText = VigenereCipher.Encrypt(HeldOutText, realKey);

        var result = VigenereSolver.Solve(cipherText);

        Assert.Equal(realKey, result.Key);
        Assert.Equal(HeldOutText, result.Plaintext);
    }

    /// <summary>
    /// A one-letter Vigenere key is just a Caesar cipher wearing a disguise. The solver should
    /// still find it correctly rather than assuming a "real" multi-letter key exists.
    /// </summary>
    [Fact]
    public void DegenerateSingleLetterKeyIsStillRecoveredCorrectly()
    {
        string cipherText = VigenereCipher.Encrypt(HeldOutText, "A"); // "A" shifts nothing at all

        var result = VigenereSolver.Solve(cipherText);

        Assert.Equal("A", result.Key);
        Assert.Equal(HeldOutText, result.Plaintext);
    }

    /// <summary>
    /// A key length that is an exact multiple of the true one produces byte-identical plaintext
    /// (the repeated key gives the same per-position shifts), so the reported key must always be
    /// reduced to its shortest repeating unit rather than left as an arbitrary multiple.
    /// </summary>
    [Fact]
    public void ReportedKeyLengthIsAlwaysTheMinimalRepeatingPeriod()
    {
        string cipherText = VigenereCipher.Encrypt(HeldOutText, "SECRET");
        var result = VigenereSolver.Solve(cipherText);

        // "SECRETSECRET" would also decrypt correctly; only "SECRET" is the minimal period.
        Assert.Equal(6, result.KeyLength);
        Assert.DoesNotMatch(@"^(.+)\1+$", result.Key); // no shorter substring repeats to fill it
    }

    [Fact]
    public void ScoreReflectsHowEnglishLikeTheRecoveredPlaintextIs()
    {
        string cipherText = VigenereCipher.Encrypt(HeldOutText, "SECRET");
        var result = VigenereSolver.Solve(cipherText);

        Assert.Equal(EnglishBigramModel.Score(result.Plaintext), result.Score, precision: 6);
    }
}
