public class KasiskiExaminationTests
{
    /// <summary>
    /// A repeated three-letter sequence, 12 letters apart, encrypted under a 6-letter key with
    /// the repeat deliberately aligned to the key (12 is a multiple of 6). The ciphertext must
    /// show the same repeated sequence at the same distance, since the key has realigned with
    /// itself by then - this is the entire mechanism Kasiski examination depends on.
    /// </summary>
    [Fact]
    public void FindsARepeatCreatedByKeyRealignment()
    {
        string plain = "ATTACKATDAWNXXXXXXATTACKATDAWN"; // "ATT" repeats at position 0 and 18
        string cipherText = VigenereCipher.Encrypt(plain, "SECRET"); // length 6; 18 is a multiple of 6

        var distances = KasiskiExamination.FindRepeatDistances(cipherText, sequenceLength: 3);

        Assert.Contains(18, distances);
    }

    /// <summary>
    /// The real signature of a true key length of 6 is not "6 gets the single highest vote" -
    /// every distance divisible by 6 is automatically also divisible by 2 and 3, so those smaller
    /// divisors structurally accumulate at least as many votes as 6 itself, usually more. The
    /// honest, correct expectation is that the true length places among the top few candidates,
    /// clustered near its own divisors - which is exactly why VigenereSolver treats this as a
    /// shortlist to cross-check against IndexOfCoincidenceAnalysis, not a standalone answer.
    /// </summary>
    [Fact]
    public void TrueKeyLengthPlacesAmongTheTopCandidates()
    {
        string plain =
            "TO SHERLOCK HOLMES SHE IS ALWAYS THE WOMAN I HAVE SELDOM HEARD HIM MENTION HER " +
            "UNDER ANY OTHER NAME IN HIS EYES SHE ECLIPSES AND PREDOMINATES THE WHOLE OF HER SEX " +
            "IT WAS NOT THAT HE FELT ANY EMOTION AKIN TO LOVE FOR IRENE ADLER ALL EMOTIONS AND " +
            "THAT ONE PARTICULARLY WERE ABHORRENT TO HIS COLD PRECISE BUT ADMIRABLY BALANCED " +
            "MIND HE WAS I TAKE IT THE MOST PERFECT REASONING AND OBSERVING MACHINE";
        string cipherText = VigenereCipher.Encrypt(plain, "SECRET");

        var votes = KasiskiExamination.EstimateKeyLength(cipherText, sequenceLength: 3, maxKeyLength: 20);
        var topFive = votes.Take(5).Select(v => v.KeyLength);

        Assert.Contains(6, topFive);
    }

    [Fact]
    public void NoRepeatsProducesNoDistances()
    {
        // Every letter distinct: guarantees no length-3 substring repeats.
        string cipherText = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var distances = KasiskiExamination.FindRepeatDistances(cipherText, sequenceLength: 3);

        Assert.Empty(distances);
    }

    [Fact]
    public void LengthOneNeverAppearsAsACandidate()
    {
        string cipherText = VigenereCipher.Encrypt(
            string.Concat(Enumerable.Repeat("ATTACKATDAWN", 10)), "KEY");

        var votes = KasiskiExamination.EstimateKeyLength(cipherText);

        Assert.DoesNotContain(votes, v => v.KeyLength == 1);
    }
}
