public class EnglishBigramModelTests
{
    [Fact]
    public void TableHasExactlyTwentySixRowsAndColumns()
    {
        Assert.Equal(26, EnglishBigramModel.LogProbabilities.GetLength(0));
        Assert.Equal(26, EnglishBigramModel.LogProbabilities.GetLength(1));
    }

    /// <summary>Every entry is a genuine log-probability: finite and negative (probabilities are <= 1).</summary>
    [Fact]
    public void EveryEntryIsAFiniteNegativeNumber()
    {
        for (int i = 0; i < 26; i++)
        {
            for (int j = 0; j < 26; j++)
            {
                double value = EnglishBigramModel.LogProbabilities[i, j];
                Assert.True(double.IsFinite(value), $"[{i},{j}] = {value} is not finite");
                Assert.True(value < 0, $"[{i},{j}] = {value} should be negative (a log-probability)");
            }
        }
    }

    /// <summary>
    /// "TH" is the single most common English digraph in every published frequency table. If the
    /// model doesn't reflect that, something went wrong in how it was built from the corpus.
    /// </summary>
    [Fact]
    public void THScoresHigherThanARareOrImpossiblePair()
    {
        double th = EnglishBigramModel.LogProbabilities['T' - 'A', 'H' - 'A'];
        double qz = EnglishBigramModel.LogProbabilities['Q' - 'A', 'Z' - 'A']; // essentially never occurs
        Assert.True(th > qz, $"Expected TH ({th}) to score higher than QZ ({qz})");
    }

    /// <summary>Genuine English prose must score higher (more probable) than the same letters scrambled.</summary>
    [Fact]
    public void RealEnglishScoresHigherThanScrambledLetters()
    {
        const string english = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG NEAR THE RIVER BANK";
        string scrambled = new(english.Where(char.IsLetter).Reverse().ToArray());

        double englishScore = EnglishBigramModel.Score(english);
        double scrambledScore = EnglishBigramModel.Score(scrambled);

        Assert.True(englishScore > scrambledScore,
            $"Expected English ({englishScore}) to score higher than scrambled text ({scrambledScore})");
    }

    [Fact]
    public void EmptyTextScoresZero() => Assert.Equal(0, EnglishBigramModel.Score(""));

    [Fact]
    public void SingleLetterScoresZero() => Assert.Equal(0, EnglishBigramModel.Score("A"));
}
