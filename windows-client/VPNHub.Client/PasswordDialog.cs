namespace VPNHub.Client;

public sealed class PasswordDialog : Form
{
    private readonly TextBox _password = new();
    private readonly TextBox _confirmation = new();

    public string Password => _password.Text;

    public PasswordDialog(string profileName)
    {
        Text = "Proteger perfil VPNHub";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(430, 225);

        var title = new Label
        {
            Text = $"Defina a senha local para \"{profileName}\".",
            AutoSize = true,
            Location = new Point(20, 18),
            Font = new Font(Font, FontStyle.Bold)
        };

        var note = new Label
        {
            Text = "A senha não será armazenada. Se ela for perdida, " +
                   "o perfil .vpnhub não poderá ser recuperado.",
            Location = new Point(20, 48),
            Size = new Size(390, 42)
        };

        var passwordLabel = new Label
        {
            Text = "Senha",
            AutoSize = true,
            Location = new Point(20, 96)
        };

        _password.Location = new Point(20, 116);
        _password.Size = new Size(390, 23);
        _password.UseSystemPasswordChar = true;

        var confirmationLabel = new Label
        {
            Text = "Confirmar senha",
            AutoSize = true,
            Location = new Point(20, 145)
        };

        _confirmation.Location = new Point(20, 165);
        _confirmation.Size = new Size(390, 23);
        _confirmation.UseSystemPasswordChar = true;

        var ok = new Button
        {
            Text = "Criar perfil",
            DialogResult = DialogResult.None,
            Location = new Point(298, 195),
            Size = new Size(112, 28)
        };

        ok.Click += (_, _) =>
        {
            if (_password.Text.Length < 12)
            {
                MessageBox.Show(
                    this,
                    "Use uma senha com pelo menos 12 caracteres.",
                    "VPNHub",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            if (!string.Equals(
                    _password.Text,
                    _confirmation.Text,
                    StringComparison.Ordinal))
            {
                MessageBox.Show(
                    this,
                    "As senhas não coincidem.",
                    "VPNHub",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            DialogResult = DialogResult.OK;
            Close();
        };

        Controls.AddRange(
        [
            title,
            note,
            passwordLabel,
            _password,
            confirmationLabel,
            _confirmation,
            ok
        ]);

        AcceptButton = ok;
    }
}
