using System.Diagnostics;
using System.Windows.Forms;

namespace DarkGreenSetup;

static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        var baseDir = AppContext.BaseDirectory;
        // EXE in dist/ → script in parent; or side-by-side after publish into connect-installer/
        var candidates = new[]
        {
            Path.GetFullPath(Path.Combine(baseDir, "DarkGreen-Setup.ps1")),
            Path.GetFullPath(Path.Combine(baseDir, "..", "DarkGreen-Setup.ps1")),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "DarkGreen-Setup.ps1")),
        };
        string? script = candidates.FirstOrDefault(File.Exists);
        if (script is null)
        {
            MessageBox.Show(
                "DarkGreen-Setup.ps1 non trovato accanto all'EXE.\nEstrai tutto lo zip connect-installer.",
                "DarkGreen SIEM Setup",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\"",
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(script) ?? baseDir,
        };
        try
        {
            Process.Start(psi)?.WaitForExit();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "DarkGreen SIEM Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
