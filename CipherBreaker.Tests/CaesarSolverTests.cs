public class CaesarSolverTests
{
    private const string PlainText =
        "ATTACK AT DAWN WHEN THE ENEMY IS LEAST PREPARED AND THE MORNING FOG STILL COVERS THE " +
        "VALLEY BELOW THE OLD BRIDGE WHERE OUR SCOUTS REPORTED THE WEAKEST POINT IN THEIR DEFENSES";

    /// <summary>
    /// The actual test of a cryptanalysis tool: give it ciphertext ONLY - no key - and confirm
    /// it recovers the right one anyway. Encrypting with CryptoPortfolio's own CaesarCipher and
    /// then handing only the ciphertext to the solver proves this is genuine attack code, not a
    /// lookup that already knows the answer.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(13)]
    [InlineData(25)]
    public void RecoversTheShiftWithNoKeyGiven(int realShift)
    {
        string cipherText = CaesarCipher.Encrypt(PlainText, realShift);

        var solved = CaesarSolver.Solve(cipherText);

        Assert.Equal(realShift, solved.Shift);
        Assert.Equal(PlainText, solved.Plaintext);
    }

    [Fact]
    public void RankAllShiftsReturnsAllTwentySixInAscendingScoreOrder()
    {
        string cipherText = CaesarCipher.Encrypt(PlainText, 7);
        var ranked = CaesarSolver.RankAllShifts(cipherText);

        Assert.Equal(26, ranked.Count);
        for (int i = 1; i < ranked.Count; i++)
        {
            Assert.True(ranked[i - 1].Score <= ranked[i].Score);
        }
    }

    /// <summary>The correct shift shouldn't just win - it should win clearly, for a message this long.</summary>
    [Fact]
    public void TheCorrectShiftScoresNotablyBetterThanTheRunnerUp()
    {
        string cipherText = CaesarCipher.Encrypt(PlainText, 11);
        var ranked = CaesarSolver.RankAllShifts(cipherText);

        Assert.Equal(11, ranked[0].Shift);
        Assert.True(ranked[1].Score > ranked[0].Score * 2,
            $"Expected a clear winner; best={ranked[0].Score}, runner-up={ranked[1].Score}");
    }

    [Fact]
    public void ShiftZeroIsRecoveredWhenTheMessageWasNeverEncrypted() =>
        Assert.Equal(0, CaesarSolver.Solve(PlainText).Shift);
}
