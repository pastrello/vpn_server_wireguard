using System.Security.Cryptography;
using VPNHub.Client.Core.Security;
using VPNHub.Client.Core.WireGuard;
using VPNHub.Client.Services;

namespace VPNHub.Client;

public sealed class MainForm : Form
{
    private readonly ProfileStore _store = new();
    private readonly WireGuardService _wireGuard = new();

    private readonly ListBox _profiles = new();
    private readonly TextBox _password = new();
    private readonly Label _state = new();
    private readonly Label _engine = new();
    private readonly Button _connect = new();
    private readonly Button _disconnect = new();
    private readonly Button _delete = new();
    private readonly System.Windows.Forms.Timer _timer = new();
    private bool _allowClose;

    public MainForm()
    {
        Text = "VPNHub Client";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(720, 440);
        ClientSize = new Size(780, 480);

        BuildUi();
        ReloadProfiles();

        _timer.Interval = 1500;
        _timer.Tick += (_, _) => RefreshState();
        _timer.Start();
        FormClosing += MainForm_FormClosing;
        FormClosed += (_, _) => _timer.Dispose();
    }

    private void BuildUi()
    {
        var header = new Label
        {
            Text = "VPNHub Client",
            Font = new Font(Font.FontFamily, 18, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(24, 20)
        };

        var subtitle = new Label
        {
            Text = "Identidade WireGuard protegida por senha local",
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Location = new Point(27, 55)
        };

        var import = new Button
        {
            Text = "Importar .conf",
            Location = new Point(24, 90),
            Size = new Size(150, 34)
        };
        import.Click += async (_, _) => await ImportProfileAsync();

        _profiles.Location = new Point(24, 138);
        _profiles.Size = new Size(270, 275);
        _profiles.Anchor =
            AnchorStyles.Top |
            AnchorStyles.Bottom |
            AnchorStyles.Left;
        _profiles.SelectedIndexChanged += (_, _) =>
        {
            RefreshState();
            UpdateButtons();
        };

        var rightLeft = 330;

        var profileLabel = new Label
        {
            Text = "Perfil selecionado",
            AutoSize = true,
            Location = new Point(rightLeft, 100)
        };

        _state.Text = "Nenhum perfil selecionado";
        _state.Font = new Font(Font, FontStyle.Bold);
        _state.AutoSize = true;
        _state.Location = new Point(rightLeft, 126);

        var passwordLabel = new Label
        {
            Text = "Senha local",
            AutoSize = true,
            Location = new Point(rightLeft, 178)
        };

        _password.Location = new Point(rightLeft, 200);
        _password.Size = new Size(410, 25);
        _password.UseSystemPasswordChar = true;
        _password.Anchor =
            AnchorStyles.Top |
            AnchorStyles.Left |
            AnchorStyles.Right;

        _connect.Text = "Conectar";
        _connect.Location = new Point(rightLeft, 245);
        _connect.Size = new Size(125, 36);
        _connect.Click += async (_, _) => await ConnectAsync();

        _disconnect.Text = "Desconectar";
        _disconnect.Location = new Point(rightLeft + 140, 245);
        _disconnect.Size = new Size(125, 36);
        _disconnect.Click += async (_, _) => await DisconnectAsync();

        _delete.Text = "Excluir perfil";
        _delete.Location = new Point(rightLeft + 280, 245);
        _delete.Size = new Size(125, 36);
        _delete.Click += async (_, _) => await DeleteAsync();

        _engine.AutoSize = true;
        _engine.Location = new Point(rightLeft, 318);
        _engine.ForeColor = SystemColors.GrayText;
        _engine.Text = _wireGuard.IsWireGuardInstalled
            ? $"WireGuard: {_wireGuard.ExecutablePath}"
            : "WireGuard oficial não encontrado.";

        var security = new Label
        {
            Text =
                "A senha é usada somente para derivar a chave Argon2id. " +
                "O arquivo .vpnhub contém a configuração WireGuard cifrada " +
                "com AES-256-GCM. A configuração temporária em claro é " +
                "removida assim que o serviço WireGuard inicia.",
            Location = new Point(rightLeft, 355),
            Size = new Size(410, 82),
            ForeColor = SystemColors.GrayText,
            Anchor =
                AnchorStyles.Left |
                AnchorStyles.Right |
                AnchorStyles.Bottom
        };

        Controls.AddRange(
        [
            header,
            subtitle,
            import,
            _profiles,
            profileLabel,
            _state,
            passwordLabel,
            _password,
            _connect,
            _disconnect,
            _delete,
            _engine,
            security
        ]);

        Resize += (_, _) =>
        {
            _password.Width = ClientSize.Width - rightLeft - 40;
            security.Width = ClientSize.Width - rightLeft - 40;
        };

        UpdateButtons();
    }

    private async void MainForm_FormClosing(
        object? sender,
        FormClosingEventArgs e)
    {
        if (_allowClose)
        {
            return;
        }

        var connected = _store.List()
            .Where(profile =>
                _wireGuard.GetState(profile.ProfileName)
                != TunnelState.Disconnected)
            .ToArray();

        if (connected.Length == 0)
        {
            _allowClose = true;
            return;
        }

        e.Cancel = true;

        var answer = MessageBox.Show(
            this,
            "Existem túneis VPNHub ativos. Eles serão desconectados " +
            "antes de fechar o cliente. Continuar?",
            "VPNHub",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (answer != DialogResult.Yes)
        {
            return;
        }

        try
        {
            SetBusy(true);

            foreach (var profile in connected)
            {
                await _wireGuard.DisconnectAsync(
                    profile.ProfileName);
            }

            _allowClose = true;
            Close();
        }
        catch (Exception exc)
        {
            ShowError(exc);
            SetBusy(false);
        }
    }

    private async Task ImportProfileAsync()
    {
        using var picker = new OpenFileDialog
        {
            Filter = "WireGuard configuration (*.conf)|*.conf",
            CheckFileExists = true,
            Multiselect = false,
            Title = "Importar configuração WireGuard"
        };

        if (picker.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        try
        {
            var config = await File.ReadAllTextAsync(
                picker.FileName);

            WireGuardConfigValidator.Validate(config);

            var profileName = Path.GetFileNameWithoutExtension(
                picker.FileName);

            using var passwordDialog = new PasswordDialog(
                profileName);

            if (passwordDialog.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            var bundle = BundleCrypto.Protect(
                profileName,
                config,
                passwordDialog.Password);

            var currentProfiles = _store.List();
            var existing = currentProfiles.FirstOrDefault(
                profile => string.Equals(
                    profile.ProfileName,
                    profileName,
                    StringComparison.OrdinalIgnoreCase));

            var tunnelName = WireGuardService.TunnelName(profileName);
            var tunnelCollision = currentProfiles.FirstOrDefault(
                profile =>
                    !string.Equals(
                        profile.ProfileName,
                        profileName,
                        StringComparison.OrdinalIgnoreCase)
                    && string.Equals(
                        WireGuardService.TunnelName(profile.ProfileName),
                        tunnelName,
                        StringComparison.OrdinalIgnoreCase));

            if (tunnelCollision is not null)
            {
                throw new InvalidDataException(
                    $"O nome \"{profileName}\" gera o mesmo tunnel service " +
                    $"do perfil \"{tunnelCollision.ProfileName}\". " +
                    "Use outro nome para o arquivo .conf.");
            }

            if (existing is not null)
            {
                var answer = MessageBox.Show(
                    this,
                    $"O perfil \"{profileName}\" já existe. Substituir?",
                    "VPNHub",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);

                if (answer != DialogResult.Yes)
                {
                    return;
                }

                if (_wireGuard.GetState(existing.ProfileName)
                    != TunnelState.Disconnected)
                {
                    await _wireGuard.DisconnectAsync(
                        existing.ProfileName);
                }

                _store.Delete(existing);
            }

            _store.Save(bundle);
            ReloadProfiles(selectName: profileName);

            var deleteSource = MessageBox.Show(
                this,
                "Perfil protegido criado. Deseja excluir o .conf original?\n\n" +
                "Observação: exclusão normal não garante apagamento físico " +
                "em SSDs.",
                "VPNHub",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (deleteSource == DialogResult.Yes)
            {
                File.Delete(picker.FileName);
            }
        }
        catch (Exception exc)
        {
            ShowError(exc);
        }
    }

    private async Task ConnectAsync()
    {
        if (_profiles.SelectedItem is not ProfileEntry profile)
        {
            return;
        }

        if (string.IsNullOrEmpty(_password.Text))
        {
            MessageBox.Show(
                this,
                "Digite a senha do perfil.",
                "VPNHub",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        byte[]? configBytes = null;

        try
        {
            SetBusy(true);

            var bundle = _store.Load(profile);
            configBytes = BundleCrypto.UnprotectBytes(
                bundle,
                _password.Text);

            await _wireGuard.ConnectAsync(
                profile.ProfileName,
                configBytes);

            _state.Text = $"{profile.ProfileName}: conectado";
        }
        catch (Exception exc)
        {
            ShowError(exc);
        }
        finally
        {
            _password.Clear();

            if (configBytes is not null)
            {
                CryptographicOperations.ZeroMemory(
                    configBytes);
            }

            SetBusy(false);
            RefreshState();
        }
    }

    private async Task DisconnectAsync()
    {
        if (_profiles.SelectedItem is not ProfileEntry profile)
        {
            return;
        }

        try
        {
            SetBusy(true);
            await _wireGuard.DisconnectAsync(
                profile.ProfileName);
        }
        catch (Exception exc)
        {
            ShowError(exc);
        }
        finally
        {
            SetBusy(false);
            RefreshState();
        }
    }

    private async Task DeleteAsync()
    {
        if (_profiles.SelectedItem is not ProfileEntry profile)
        {
            return;
        }

        var answer = MessageBox.Show(
            this,
            $"Excluir o perfil protegido \"{profile.ProfileName}\"?",
            "VPNHub",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);

        if (answer != DialogResult.Yes)
        {
            return;
        }

        try
        {
            SetBusy(true);
            await _wireGuard.DisconnectAsync(
                profile.ProfileName);
            _store.Delete(profile);
            ReloadProfiles();
        }
        catch (Exception exc)
        {
            ShowError(exc);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void ReloadProfiles(string? selectName = null)
    {
        var profiles = _store.List();

        _profiles.BeginUpdate();
        _profiles.Items.Clear();

        foreach (var profile in profiles)
        {
            _profiles.Items.Add(profile);
        }

        _profiles.EndUpdate();

        if (profiles.Count > 0)
        {
            var index = selectName is null
                ? 0
                : profiles
                    .Select((profile, index) => (profile, index))
                    .Where(item => string.Equals(
                        item.profile.ProfileName,
                        selectName,
                        StringComparison.OrdinalIgnoreCase))
                    .Select(item => item.index)
                    .DefaultIfEmpty(0)
                    .First();

            _profiles.SelectedIndex = index;
        }

        RefreshState();
        UpdateButtons();
    }

    private void RefreshState()
    {
        if (_profiles.SelectedItem is not ProfileEntry profile)
        {
            _state.Text = "Nenhum perfil selecionado";
            UpdateButtons();
            return;
        }

        var state = _wireGuard.GetState(
            profile.ProfileName);

        _state.Text = state switch
        {
            TunnelState.Connected =>
                $"{profile.ProfileName}: conectado",
            TunnelState.Connecting =>
                $"{profile.ProfileName}: conectando...",
            TunnelState.Disconnecting =>
                $"{profile.ProfileName}: desconectando...",
            _ =>
                $"{profile.ProfileName}: desconectado"
        };

        UpdateButtons();
    }

    private void UpdateButtons()
    {
        var hasProfile =
            _profiles.SelectedItem is ProfileEntry;

        _connect.Enabled =
            hasProfile &&
            _wireGuard.IsWireGuardInstalled;

        _disconnect.Enabled =
            hasProfile &&
            _wireGuard.IsWireGuardInstalled;

        _delete.Enabled = hasProfile;
        _password.Enabled = hasProfile;
    }

    private void SetBusy(bool busy)
    {
        UseWaitCursor = busy;
        _profiles.Enabled = !busy;
        _connect.Enabled = !busy;
        _disconnect.Enabled = !busy;
        _delete.Enabled = !busy;
    }

    private void ShowError(Exception exc)
    {
        MessageBox.Show(
            this,
            exc.Message,
            "VPNHub Client",
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);
    }
}
