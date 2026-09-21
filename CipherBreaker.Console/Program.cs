using System;
using System.Linq;

public class Program
{
    public static void Main(string[] args)
    {
        while (true)
        {
            Console.WriteLine("\n=== CipherBreaker ===");
            Console.WriteLine("Attacks that recover a key or plaintext WITHOUT being told the key.");
            Console.WriteLine();
            Console.WriteLine(" 1. Caesar solver (brute force + chi-squared scoring)");
            Console.WriteLine(" 2. Simple substitution solver (hill-climbing + bigram scoring)");
            Console.WriteLine(" 3. Vigenere solver (Kasiski + Index of Coincidence + Caesar solver)");
            Console.WriteLine(" 4. Hill known-plaintext attack (exact linear algebra)");
            Console.WriteLine(" 5. Analyse text (letter frequencies, chi-squared, index of coincidence)");
            Console.WriteLine(" 6. Exit");
            Console.Write("\nEnter your choice: ");

            string choice = (Console.ReadLine() ?? "").Trim();

            switch (choice)
            {
                case "1": RunCaesarSolver(); break;
                case "2": RunSimpleSubstitutionSolver(); break;
                case "3": RunVigenereSolver(); break;
                case "4": RunHillKnownPlaintextAttack(); break;
                case "5": RunFrequencyAnalysis(); break;
                case "6": Console.WriteLine("Exiting program. Goodbye!"); return;
                default: Console.WriteLine("Invalid choice."); break;
            }

            Console.WriteLine("\nPress any key to return to the main menu...");
            if (Console.IsInputRedirected) return;
            Console.ReadKey();
            Console.Clear();
        }
    }

    private static void RunCaesarSolver()
    {
        Console.WriteLine("\n--- Caesar Solver ---");
        Console.WriteLine("No key needed: paste ciphertext, and every shift is tried and scored.");
        Console.Write("Enter ciphertext: ");
        string cipherText = Console.ReadLine() ?? "";

        var ranked = CaesarSolver.RankAllShifts(cipherText);

        Console.WriteLine("\nRank  Shift  Score       Plaintext");
        for (int i = 0; i < ranked.Count; i++)
        {
            var c = ranked[i];
            Console.WriteLine($"{i + 1,4}  {c.Shift,5}  {c.Score,9:F2}   {c.Plaintext}");
        }

        var best = ranked[0];
        Console.WriteLine($"\nBest guess: shift {best.Shift} -> {best.Plaintext}");
    }

    private static void RunSimpleSubstitutionSolver()
    {
        Console.WriteLine("\n--- Simple Substitution Solver ---");
        Console.WriteLine("No key needed: hill-climbs a 26-letter key against real English bigram");
        Console.WriteLine("statistics. Works best with a few hundred letters or more; short messages");
        Console.WriteLine("may leave the rarest letters (J, Q, X, Z) ambiguous even when everything");
        Console.WriteLine("else resolves correctly - that is a genuine statistical limit, not a bug.");
        Console.Write("\nEnter ciphertext: ");
        string cipherText = Console.ReadLine() ?? "";

        Console.WriteLine("Searching (this can take a few seconds for longer messages)...");
        var result = SimpleSubstitutionSolver.Solve(cipherText);

        Console.WriteLine($"\nBest key found: {result.Key}");
        Console.WriteLine($"Score: {result.Score:F2}");
        Console.WriteLine($"\nRecovered plaintext:\n{result.Plaintext}");
    }

    private static void RunVigenereSolver()
    {
        Console.WriteLine("\n--- Vigenere Solver ---");
        Console.WriteLine("No key needed: estimates the key length from repeated sequences");
        Console.WriteLine("(Kasiski) and column statistics (Index of Coincidence), then attacks");
        Console.WriteLine("each key position as its own Caesar cipher. Works best with at least a");
        Console.WriteLine("few hundred letters, since key-length estimation needs enough repeats.");
        Console.Write("\nEnter ciphertext: ");
        string cipherText = Console.ReadLine() ?? "";

        var result = VigenereSolver.Solve(cipherText);

        Console.WriteLine($"\nKey length found: {result.KeyLength}");
        Console.WriteLine($"Key: {result.Key}");
        Console.WriteLine($"\nRecovered plaintext:\n{result.Plaintext}");
    }

    private static void RunHillKnownPlaintextAttack()
    {
        Console.WriteLine("\n--- Hill Known-Plaintext Attack ---");
        Console.WriteLine("Different from every other solver here: this needs a CRIB, not just");
        Console.WriteLine("ciphertext - plaintext you know or suspect appears somewhere in the");
        Console.WriteLine("message. You don't need to know WHERE; at least 4 letters of crib are");
        Console.WriteLine("needed, and this is exact linear algebra, not a statistical guess.");
        Console.Write("\nEnter ciphertext: ");
        string cipherText = Console.ReadLine() ?? "";
        Console.Write("Enter known/suspected plaintext (the crib): ");
        string crib = Console.ReadLine() ?? "";

        var result = HillKnownPlaintextAttack.Recover(cipherText, crib);

        if (!result.Success)
        {
            Console.WriteLine($"\nNo key recovered: {result.Error}");
            return;
        }

        Console.WriteLine($"\nKey recovered: {result.Key}");
        Console.WriteLine($"Crib found at letter offset: {result.PlaintextOffset}");
        Console.WriteLine($"\nFull plaintext:\n{result.Plaintext}");
    }

    private static void RunFrequencyAnalysis()
    {
        Console.WriteLine("\n--- Frequency Analysis ---");
        Console.Write("Enter text: ");
        string text = Console.ReadLine() ?? "";

        var counts = FrequencyAnalysis.Counts(text);
        int total = counts.Values.Sum();

        Console.WriteLine($"\nLetters analysed: {total}");
        Console.WriteLine("Letter  Count   Observed%   English%");
        foreach (var (letter, count) in counts.OrderByDescending(kv => kv.Value))
        {
            if (count == 0) continue;
            double observedPercent = total > 0 ? count * 100.0 / total : 0;
            double englishPercent = FrequencyAnalysis.EnglishFrequencies[letter];
            Console.WriteLine($"{letter,5}   {count,5}   {observedPercent,8:F2}%   {englishPercent,7:F2}%");
        }

        Console.WriteLine($"\nChi-squared vs. English: {FrequencyAnalysis.ChiSquared(text):F2} (lower = more English-like)");
        Console.WriteLine($"Index of Coincidence:    {FrequencyAnalysis.IndexOfCoincidence(text):F4}");
        Console.WriteLine("  (English prose ~0.067; a uniformly random 26-letter alphabet ~0.0385.");
        Console.WriteLine("   Near 0.067 suggests plain text or monoalphabetic substitution;");
        Console.WriteLine("   noticeably lower suggests polyalphabetic substitution, e.g. Vigenere.)");
    }
}
