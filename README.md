# Zore Client Inspector

A PowerShell screenshare tool for Minecraft server staff. It inspects the
**running** Minecraft instance and its mods folder for cheat clients, hacked
mods, ghost clients and malware, then gives a colour-coded verdict.

It only reads: files, the game's memory (read-only) and Windows' program
history. Nothing is changed or deleted. Network access goes only to the public
Modrinth API: SHA-1 hashes of the mod jars to recognise known-good mods, and
official mod files to compare suspected tampered copies against.

## Run it

Open PowerShell (Windows key -> type `PowerShell` -> Enter) and paste:

```powershell
irm https://raw.githubusercontent.com/wesskolen1-sys/zore-client-inspector/main/ZoreClientInspector.ps1 | iex
```

It downloads and starts straight away. Nothing is saved to disk.

**Prefer clicking?** Download the launcher
[ZoreInspector.bat](https://github.com/wesskolen1-sys/zore-client-inspector/releases/latest/download/ZoreInspector.bat)
and open it. It runs the same command, so it always starts the newest version.
Windows may ask "Do you want to run this file?": click **Run**. On a blue
"Windows protected your PC" screen, click **More info -> Run anyway**.

1. If PowerShell is not running as Administrator, Windows asks once. Click
   **Yes** and the scan opens in a new window. Clicking No continues with a
   limited scan.
2. At `PATH:`, press Enter to scan the running Minecraft instance's mods
   folder, or paste another mods folder / jar.
3. Read the verdict at the bottom. Type `Y` to save the report to the Desktop.

Start Minecraft first so the live checks (process, injected DLLs, game memory)
can run.

From a downloaded copy instead:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\ZoreClientInspector.ps1
```

## What it checks

| Step | Checks |
| --- | --- |
| 1. Live game | Window title, `--version` / launcher brand, `-javaagent` injections, native agents (`-agentpath` / `-agentlib`, including the JDWP debugger), attach-enabling flags, `-Dfabric.addMods`, cheat jars on the classpath, Minecraft jar tampering (SHA-1 vs Mojang), unsigned DLLs loaded into `javaw.exe`, DLLs whose file was deleted, Java agents attached while the game runs (`instrument.dll` loaded without `-javaagent`) |
| 2. Modrinth | Hashes every jar. Exact matches with a published Modrinth file count as verified. Your own known-bad hashes are matched here too. |
| 3. Deep scan | Every jar, including bundled jar-in-jar libraries. Jars that are not verified are scored; verified ones are only read so the memory scan knows what they contain. See below. |
| 4. Game memory | Injected clients: reads the running game's memory (read-only) for cheat module names and cheat-client code that **no jar on disk contains**. Also finds DLLs hidden from the module list and manually mapped DLLs. |
| 5. Traces | Cheat-client data folders/configs (`meteor-client`, `wurst`, `Prestige`, `Argon`, ...) in the game folder, `config`, AppData and the user folder; cheat versions in `versions`; cheat jars in other launcher instances (Prism Launcher, CurseForge, Modrinth App, ATLauncher, GDLauncher); Recycle Bin; Desktop/Downloads; **execution history** (UserAssist, BAM, Prefetch) |
| 6. Programs | Ghost-client loaders, auto-clickers / macro tools, DLL injectors, jar editors |

### The deep scan

- **Known clients:** code packages of Meteor, Wurst, LiquidBounce/FDP,
  Aristois, Future, RusherHack, KAMI/Lambda, Phobos, 3arthh4ck, Boze,
  ThunderHack, Argon, Raven, Rise, Sigma, Novoline, Tenacity, Exhibition,
  Vestige, Augustus, OyVey, GameSense, Mio, Baritone and more.
- **Addons and plugins** for cheat clients: Meteor addons, RusherHack plugins,
  and anything that uses a cheat client's API.
- **Cheat modules:** about 250 module and setting names (about 1,300 keyword
  variants) across:
  - combat: KillAura, AimAssist, TriggerBot, AutoClicker, Reach, Velocity, WTap, FakeLag ...
  - crystal / anchor / totem PvP: AutoCrystal, AnchorMacro, AutoDoubleHand, HoverTotem, KeyPearl, ShieldBreaker, MaceSwap ...
  - movement: Flight, PacketFly, BoatFly, Speed, Scaffold, NoFall, Jesus, Spider ...
  - render: ESP, StorageESP, Chams, Tracers, XRay, Wallhack, ClickGUI ...
  - exploits: Nuker, SpeedMine, Crasher, Dupe ...
  - anticheat bypasses: Grim, Vulcan, Verus, Matrix, NCP ...

  Matching uses class names (`KillAura.class`, `ModuleKillAura`,
  `KillauraHack`) and the text inside class files, so renamed jars are still
  caught. Ordinary words like `Speed` or `Flight` only count inside a
  `modules/` / `hacks/` folder.
- **Ghost-client hiding tricks:** encrypted `.class` files, classes, jars or
  `.exe` files hidden under other file names (e.g. `icon.png`), encrypted data
  blobs, duplicate zip entries, fake `.class/` folders, heavy obfuscation,
  obfuscator watermarks (Allatori, ZKM, Skidfuscator, Branchlock, ...) and
  native obfuscation (JNIC, j2cc).
- **Behaviour:** loaders that decrypt or download code and define classes at
  runtime, hardware-ID (HWID) license checks, anti-screenshare code that looks
  for AnyDesk / Echo / Process Hacker etc., real mouse-input simulation
  (`java.awt.Robot`, `SendInput`), and code that triggers attacks.
- **Malware:** token, browser, Minecraft-account and wallet stealers, and
  Discord webhooks. These are flagged as **MALWARE**.
- **Tampered official mods:** a jar that claims to be a Modrinth mod (by its
  mod id and name) but is not one of its published files is compared file by
  file with the official release of the same file name or version. Extra or
  changed code, such as a cheat hidden inside a copy of Clumps or Sodium, gives
  **CHEAT**. Changed resources give SUSPICIOUS. A plain re-zip is not flagged.
- **Packaging:** missing mod metadata, Java-agent jars, coremods/tweakers,
  bundled programs, jars named like popular mods that contain something else,
  files added after the game started, hidden files, and the download source
  (Zone.Identifier).

Results are graded **MALWARE**, **CHEAT**, **SUSPICIOUS**, **REVIEW**,
**UNKNOWN** (not on Modrinth but nothing found) and **VERIFIED**. A report can
be saved to the Desktop.

False positives: every signature was tested against 80 popular legit mods
(Sodium, Create, Mekanism, Quark, Distant Horizons, Axiom, Wynntils, Replay
Mod, ...), deep-scanned as if they were unknown. Only the real Auto Clicker
mod, Tweakeroo and Freecam are flagged, and those are mods many servers ban.

Speed: keyword search runs in one pass using a small compiled matcher
(Aho-Corasick via `Add-Type`). A 20 MB mod scans in under a second. If
`Add-Type` is blocked, a slower regex fallback is used automatically.

## Injected clients

Injectable clients (Vape, Drip, Slinky, ...) never put a jar in the mods folder.
The inspector looks for what they leave behind instead:

- **In the game's memory:** their module names (KillAura, AimAssist, Hover
  Totem ...) and package names. Hits are only counted when no jar on disk
  explains them, so this also catches a cheat jar that was deleted after it
  loaded. Four or more unexplained module names give **CHEAT**, two or three
  give SUSPICIOUS, and one gives REVIEW (often just chat text). Each finding
  shows the surrounding text from memory so staff can judge it. A 4 GB heap
  takes a few seconds (4 scanning threads).
- **In the game process:** unsigned DLLs, DLLs whose file was deleted, DLLs
  hidden from the module list, manually mapped DLLs, and Java agents attached
  at runtime or at launch (`-javaagent`, `-agentpath`, `-agentlib`, JDWP).
- **In Windows' program history:** loaders, injectors and auto-clickers that
  were run, and unknown programs that ran from Downloads/Desktop/Temp while the
  game was open and have since been deleted. UserAssist works without admin;
  BAM and Prefetch need admin.

Antivirus note: the memory scanner is compiled at runtime (`Add-Type`) and
reads another process's memory, which some antivirus programs dislike. If it is
blocked, the inspector says so and runs every other check.

## Ghost clients (e.g. Prestige)

Paid ghost clients like Prestige are closed-source and change between builds,
so there is no public sample to fingerprint. The inspector catches them through
the things such clients have to do:

- **The name:** "prestige" in file, mod, folder, config, process or window names.
- **What they sell:** crystal/anchor/totem PvP modules.
- **How they hide:** obfuscation, encryption, loaders, HWID checks and
  anti-screenshare code.

Once you have a sample (for example from a banned player), add its SHA-1 so
it is matched exactly. Put lines like the following in
`%APPDATA%\ZoreInspector\signatures.txt`, or in a file or URL named by the
`ZORE_SIGNATURES` environment variable:

```
0123456789abcdef0123456789abcdef01234567 Prestige Client 1.x
```

## Limits

No scanner can promise that a player is clean. Clients that encrypt their
strings in memory, wipe their DLL headers, unload before the scan, or are
cleaned from the history can still slip past. Kernel-level cheats are out of
reach of any PowerShell tool. Use it together with a normal screenshare.

The memory, DLL and execution-history checks only run on Windows and have only
been tested with simulated data, not against a real injected client.

## Automation

| Variable | Effect |
| --- | --- |
| `ZORE_PATH` | Folder or jar to scan; skips the `PATH:` prompt |
| `ZORE_SAVE` | `Y`/`N`, answers the save-report prompt |
| `ZORE_NO_PAUSE` | `1` skips "Press Enter to exit" |
| `ZORE_SIGNATURES` | File path or URL with extra `<sha1> <name>` signatures |
| `ZORE_NO_ELEVATE` | `1` never relaunches as Administrator |
