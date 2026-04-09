<#
.SYNOPSIS
    Tray app that watches the Windows clipboard and syncs images
    into Docker containers' X11 clipboard (Xvfb) automatically.

.DESCRIPTION
    The host-side tray app only writes PNG to a bind-mounted directory.
    Inside each container, clipboard-watch daemon detects the new file
    and loads it into X11 clipboard via xclip. No docker exec needed -
    sync is near-instant (<500ms).

.EXAMPLE
    wscript clipboard-image-tray.vbs
#>

# -- Single instance check (named mutex) --
$mutexName = 'Global\ClipboardImageTraySync'
$script:mutex = New-Object System.Threading.Mutex($false, $mutexName)
if (-not $script:mutex.WaitOne(0, $false)) {
    # Already running - show a message and exit
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        "Clipboard Sync is already running (check system tray).",
        "Clipboard Sync",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    exit 0
}

# Hide the console window
Add-Type -Name Win32 -Namespace Native -MemberDefinition @'
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]   public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
$null = [Native.Win32]::ShowWindow([Native.Win32]::GetConsoleWindow(), 0)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# -- Globals --
$script:lastHash    = ""
$script:paused      = $false
$script:syncCount   = 0
$script:syncDir     = Join-Path $env:TEMP "cb-x11-sync"
if (-not (Test-Path $script:syncDir)) { New-Item -ItemType Directory -Path $script:syncDir | Out-Null }
$script:tmpFile     = Join-Path $script:syncDir "img.png"

# -- Draw tray icons (16x16, different colors per state) --
function New-TrayIcon([string]$state) {
    $bmp = New-Object System.Drawing.Bitmap(16, 16)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    switch ($state) {
        "idle"   { $body = [System.Drawing.Color]::FromArgb(255,90,90,90);   $accent = [System.Drawing.Color]::FromArgb(255,160,160,160) }
        "active" { $body = [System.Drawing.Color]::FromArgb(255,30,140,60);  $accent = [System.Drawing.Color]::FromArgb(255,100,220,130) }
        "paused" { $body = [System.Drawing.Color]::FromArgb(255,180,140,20); $accent = [System.Drawing.Color]::FromArgb(255,240,200,60)  }
        "error"  { $body = [System.Drawing.Color]::FromArgb(255,180,40,40);  $accent = [System.Drawing.Color]::FromArgb(255,240,80,80)   }
    }

    $penOutline = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255,40,40,40), 1)
    $brushBody  = New-Object System.Drawing.SolidBrush $body
    $brushClip  = New-Object System.Drawing.SolidBrush $accent
    $brushWhite = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)

    # Clipboard body
    $g.FillRectangle($brushBody, 1, 3, 14, 12)
    $g.DrawRectangle($penOutline, 1, 3, 13, 11)

    # Clipboard clip (top center)
    $g.FillRectangle($brushClip, 4, 0, 8, 5)
    $g.DrawRectangle($penOutline, 4, 0, 7, 4)
    $g.FillRectangle($brushBody, 5, 1, 6, 3)
    $g.DrawRectangle($penOutline, 5, 1, 5, 2)

    # Image icon inside clipboard (sun + mountains)
    $g.FillEllipse($brushWhite, 4, 6, 3, 3)
    $penWhite = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 1.5)
    $g.DrawLine($penWhite, 3, 13, 7, 8)
    $g.DrawLine($penWhite, 7, 8, 9, 10)
    $g.DrawLine($penWhite, 9, 10, 11, 7)
    $g.DrawLine($penWhite, 11, 7, 13, 13)

    $g.Dispose()
    $penOutline.Dispose()
    $brushBody.Dispose()
    $brushClip.Dispose()
    $brushWhite.Dispose()

    return [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
}

$iconIdle    = New-TrayIcon "idle"
$iconActive  = New-TrayIcon "active"
$iconPaused  = New-TrayIcon "paused"
$iconError   = New-TrayIcon "error"

# -- Tray setup --
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon    = $iconIdle
$notify.Text    = "Clipboard Sync - watching"
$notify.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip

$menuStatus = $menu.Items.Add("Watching clipboard")
$menuStatus.Enabled = $false

$menu.Items.Add("-")

$menuPause = $menu.Items.Add("Pause")
$menuPause.Add_Click({
    $script:paused = -not $script:paused
    if ($script:paused) {
        $menuPause.Text = "Resume"
        $notify.Icon    = $iconPaused
        $notify.Text    = "Clipboard Sync - paused"
    } else {
        $menuPause.Text = "Pause"
        $notify.Icon    = $iconIdle
        $notify.Text    = "Clipboard Sync - watching"
    }
})

$menu.Items.Add("-")

$menuExit = $menu.Items.Add("Exit")
$menuExit.Add_Click({
    $timer.Stop()
    $notify.Visible = $false
    $notify.Dispose()
    $script:mutex.ReleaseMutex()
    $script:mutex.Dispose()
    [System.Windows.Forms.Application]::Exit()
})

$notify.ContextMenuStrip = $menu

# -- Quick fingerprint (size + corner pixels, avoids full PNG encode) --
function Get-ImageFingerprint([System.Drawing.Image]$img) {
    $bmp = [System.Drawing.Bitmap]$img
    $fp = "$($bmp.Width)x$($bmp.Height)"
    $fp += $bmp.GetPixel(0, 0).ToArgb()
    $fp += $bmp.GetPixel([math]::Min(1, $bmp.Width-1), 0).ToArgb()
    $fp += $bmp.GetPixel(0, [math]::Min(1, $bmp.Height-1)).ToArgb()
    $fp += $bmp.GetPixel([math]::Floor($bmp.Width/2), [math]::Floor($bmp.Height/2)).ToArgb()
    return $fp
}

# -- Sync function --
function Sync-ClipboardImage {
    if ($script:paused) { return }

    try {
        $img = [System.Windows.Forms.Clipboard]::GetImage()
        if (-not $img) { return }

        $hash = Get-ImageFingerprint $img
        if ($hash -eq $script:lastHash) { return }

        # Save to bind-mounted dir - container watcher picks it up automatically
        $img.Save($script:tmpFile, [System.Drawing.Imaging.ImageFormat]::Png)
        $size = (Get-Item $script:tmpFile).Length

        $script:lastHash = $hash
        $script:syncCount++
        $kb = [math]::Round($size / 1024)

        $notify.Icon = $iconActive
        $notify.Text = "Clipboard Sync - #$($script:syncCount)"
        $menuStatus.Text = "Last: $($img.Width)x$($img.Height) ${kb}KB (#$($script:syncCount))"
        $notify.ShowBalloonTip(1000, "Image captured", "$($img.Width)x$($img.Height) ${kb}KB", [System.Windows.Forms.ToolTipIcon]::Info)

        # Reset icon to idle after 1 second
        $resetTimer = New-Object System.Windows.Forms.Timer
        $resetTimer.Interval = 1000
        $resetTimer.Add_Tick({
            if (-not $script:paused) { $notify.Icon = $iconIdle }
            $this.Stop()
            $this.Dispose()
        })
        $resetTimer.Start()

    } catch {
        # Clipboard busy or other transient error - skip this tick
    }
}

# -- Poll timer --
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 300
$timer.Add_Tick({ Sync-ClipboardImage })
$timer.Start()

$notify.ShowBalloonTip(2000, "Clipboard Sync", "Watching for images. Containers pick up via bind mount.", [System.Windows.Forms.ToolTipIcon]::Info)

# -- Run --
[System.Windows.Forms.Application]::Run()
