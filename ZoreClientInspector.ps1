<#
    ZORE CLIENT INSPECTOR
    =====================
    Scans the running Minecraft instance (and its mods folder) for cheat
    clients, hacked mods and other suspicious files. Built for server staff
    doing screenshares.

    Run it straight from PowerShell (needs the file to be publicly reachable):

        irm https://raw.githubusercontent.com/wesskolen1-sys/zore-client-inspector/main/ZoreClientInspector.ps1 | iex

    or from a downloaded copy:

        powershell -NoProfile -ExecutionPolicy Bypass -File .\ZoreClientInspector.ps1

    Works on Windows PowerShell 5.1 and PowerShell 7+. It only reads: files,
    the game's memory (read-only) and Windows' program history. Nothing is
    changed or deleted. Network access goes only to the public Modrinth API:
    SHA-1 hashes of the mod jars (to recognise known-good mods) and official
    mod files (to compare suspected tampered copies against).
    Run it as Administrator from 64-bit PowerShell for every check.

    Optional environment variables (for automation):
        ZORE_PATH   mods folder / jar to scan, skips the PATH prompt
        ZORE_SAVE   Y or N, answers the "save report" prompt
        ZORE_NO_PAUSE   set to 1 to skip "Press Enter to exit"
        ZORE_NO_ELEVATE set to 1 to never relaunch as Administrator
        ZORE_SIGNATURES file path or URL with extra "<sha1> <name>" lines
                        (also read from %APPDATA%\ZoreInspector\signatures.txt)

    This file is plain ASCII on purpose: Windows PowerShell 5.1 reads BOM-less
    scripts with the ANSI code page, so every block and box character in the
    banner is built at runtime from its code point.
#>

& {

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'   # Invoke-RestMethod is far slower with the progress bar on 5.1

# =============================================================================
#  Settings
# =============================================================================
$ZoreVersion  = '1.4.0'
# Public copy of this script: used to relaunch it as Administrator when it was
# started with  irm <url> | iex  (there is no file to relaunch then).
$ZoreScriptUrl = 'https://raw.githubusercontent.com/wesskolen1-sys/zore-client-inspector/main/ZoreClientInspector.ps1'
$ZoreCredit   = 'Zore'
$UserAgent    = "ZoreClientInspector/$ZoreVersion"
$MaxDeepJar   = 250MB   # bigger jars are hashed and name-checked only
$MaxNestedJar = 64MB    # bundled (jar-in-jar) libraries larger than this are skipped
$MaxClassSize = 4MB     # a single .class file larger than this is skipped
$ChunkSize    = 8MB     # class bytes are regex-scanned in chunks of this size

$IsWin   = ($env:OS -eq 'Windows_NT')
$AppData = $env:APPDATA;     if (-not $AppData) { $AppData = $HOME }
$UserDir = $env:USERPROFILE; if (-not $UserDir) { $UserDir = $HOME }

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
foreach ($asm in @('System.IO.Compression', 'System.IO.Compression.FileSystem')) {
    try { Add-Type -AssemblyName $asm -ErrorAction Stop } catch { }
}
try { $Host.UI.RawUI.WindowTitle = "Zore Client Inspector v$ZoreVersion" } catch { }

$Latin1 = [System.Text.Encoding]::GetEncoding(28591)
$RxOpt  = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
$RxFast = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant, Compiled'

# =============================================================================
#  Characters (built from code points, see the note at the top)
# =============================================================================
$Ch = @{
    Block = [string][char]0x2588
    DH    = [string][char]0x2550
    DV    = [string][char]0x2551
    DTL   = [string][char]0x2554
    DTR   = [string][char]0x2557
    DBL   = [string][char]0x255A
    DBR   = [string][char]0x255D
    Heavy = [string][char]0x2501
    Heart = [string][char]0x2665
}
$ArtMap = @{ '#' = $Ch.Block; ']' = $Ch.DTR; '[' = $Ch.DTL; '{' = $Ch.DBL; '}' = $Ch.DBR; '=' = $Ch.DH; '|' = $Ch.DV }

# "ZORE CLIENT" / "INSPECTOR" in a block font. # is a full block, the other
# symbols are the double-line shadow (see $ArtMap).
$BannerArt = @(
    '#######] ######] ######] #######]     ######]##]     ##]#######]###]   ##]########]'
    '{==###[}##[===##]##[==##]##[====}    ##[====}##|     ##|##[====}####]  ##|{==##[==}'
    '  ###[} ##|   ##|######[}#####]      ##|     ##|     ##|#####]  ##[##] ##|   ##|'
    ' ###[}  ##|   ##|##[==##]##[==}      ##|     ##|     ##|##[==}  ##|{##]##|   ##|'
    '#######]{######[}##|  ##|#######]    {######]#######]##|#######]##| {####|   ##|'
    '{======} {=====} {=}  {=}{======}     {=====}{======}{=}{======}{=}  {===}   {=}'
    ''
    '      ##]###]   ##]#######]######] #######] ######]########] ######] ######]'
    '      ##|####]  ##|##[====}##[==##]##[====}##[====}{==##[==}##[===##]##[==##]'
    '      ##|##[##] ##|#######]######[}#####]  ##|        ##|   ##|   ##|######[}'
    '      ##|##|{##]##|{====##|##[===} ##[==}  ##|        ##|   ##|   ##|##[==##]'
    '      ##|##| {####|#######|##|     #######]{######]   ##|   {######[}##|  ##|'
    '      {=}{=}  {===}{======}{=}     {======} {=====}   {=}    {=====} {=}  {=}'
)

$Mascot = @(
    '                                .-"""""-.'
    '                              .`  .---.  `.'
    '                             /   /  _  \   \'
    '                            |   |  (_)  |   |'
    '                             \   \     /   /'
    '                              `.  `---`  .`\'
    '                                `-.....-` \ \'
    '                                           \ \'
    '                                            \_\'
)

# =============================================================================
#  Signatures
# =============================================================================

# --- Known cheat clients ------------------------------------------------------

# Package folders that only exist inside cheat clients. A package that is wrong
# or outdated can never cause a false positive (no legit mod uses them), so this
# list errs on the side of including more.
$CheatPackages = [ordered]@{
    'meteordevelopment/meteorclient/' = 'Meteor Client'
    'anticope/rejects/'               = 'Meteor Rejects (Meteor addon)'
    'net/wurstclient/'                = 'Wurst Client'
    'net/ccbluex/liquidbounce/'       = 'LiquidBounce / FDPClient'
    'me/deftware/'                    = 'Aristois (EMC framework)'
    'net/futureclient/'               = 'Future Client'
    'org/rusherhack/'                 = 'RusherHack'
    'me/zeroeightsix/kami/'           = 'KAMI'
    'org/kamiblue/'                   = 'KAMI Blue'
    'com/lambda/client/'              = 'Lambda'
    'me/ionar/salhack/'               = 'SalHack'
    'me/earth/phobos/'                = 'Phobos'
    'me/earth/earthhack/'             = '3arthh4ck'
    'me/rigamortis/seppuku/'          = 'Seppuku'
    'org/bleachhack/'                 = 'BleachHack'
    'bleach/hack/'                    = 'BleachHack'
    'thunder/hack/'                   = 'ThunderHack'
    'dev/boze/'                       = 'Boze'
    'coffee/client/'                  = 'Coffee Client'
    'me/dustin/jex/'                  = 'Jex Client'
    'dev/tigr/ares/'                  = 'Ares'
    'net/aoba/'                       = 'Aoba'
    'dev/lvstrng/argon/'              = 'Argon (ghost client)'
    'cc/novoline/'                    = 'Novoline'
    'com/mentalfrostbyte/jello/'      = 'Sigma / Jello'
    'net/impactclient/'               = 'Impact'
    'me/alpha432/oyvey/'              = 'OyVey'
    'me/travis/wurstplus/'            = 'WurstPlus'
    'com/gamesense/client/'           = 'GameSense'
    'com/elementars/eclient/'         = 'Xulu'
    'me/mioclient/'                   = 'Mio'
    'dev/blackout/'                   = 'BlackOut'
    'keystrokesmod/client/module/'    = 'Raven (B+ / bS / XD)'
    'com/alan/clients/'               = 'Rise'
    'dev/tenacity/'                   = 'Tenacity'
    'exhibition/'                     = 'Exhibition'
    'vestige/'                        = 'Vestige'
    'net/augustus/'                   = 'Augustus'
    'baritone/'                       = 'Baritone (automation bot)'
}
$CheatPackageRx = [regex]::new('^(' + ((@($CheatPackages.Keys) | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')', $RxFast)

# Cheat-client APIs. A jar that *uses* one of these is an addon/plugin for it.
$CheatApis = [ordered]@{
    'meteordevelopment/meteorclient/' = 'Meteor Client'
    'net/wurstclient/'                = 'Wurst Client'
    'org/rusherhack/client/api/'      = 'RusherHack'
    'net/ccbluex/liquidbounce/'       = 'LiquidBounce'
    'me/deftware/client/framework/'   = 'Aristois / EMC'
    'thunder/hack/'                   = 'ThunderHack'
    'dev/boze/'                       = 'Boze'
    'com/lambda/client/'              = 'Lambda'
    'org/kamiblue/'                   = 'KAMI Blue'
}

# Mod ids (fabric.mod.json / mods.toml) of known cheat clients. Also used to
# spot addons, which list the client as a dependency.
$CheatModIds = @{
    'meteor-client' = 'Meteor Client';  'wurst'      = 'Wurst Client';  'liquidbounce'   = 'LiquidBounce'
    'aristois'      = 'Aristois';       'rusherhack' = 'RusherHack';    'bleachhack'     = 'BleachHack'
    'thunderhack'   = 'ThunderHack';    'boze'       = 'Boze';          'coffeeclient'   = 'Coffee Client'
    'kamiblue'      = 'KAMI Blue';      'salhack'    = 'SalHack';       'konas'          = 'Konas'
    'baritone'      = 'Baritone';       'aoba'       = 'Aoba';          'argonclient'    = 'Argon'
    'jex'           = 'Jex Client';     'seppuku'    = 'Seppuku';       'futureclient'   = 'Future Client'
    'meteor-rejects' = 'Meteor Rejects'; 'prestigeclient' = 'Prestige Client'; 'prestige-client' = 'Prestige Client'
}

# Names of cheat clients / cheat features. Used on file names, mod names,
# version folders, window titles, java agents, the Recycle Bin and Downloads.
$CheatNameRx = [regex]::new(('(?:meteor[\s_-]?(?:client|rejects)|(?<![a-z])wurst|liquid[\s_-]?bounce|aristois|rusher[\s_-]?hack|' +
    'bleach[\s_-]?hack|thunder[\s_-]?hack|kami[\s_-]?blue|sal[\s_-]?hack|3arthh4ck|earthhack|seppuku|future[\s_-]?client|' +
    'impact[\s_-]?client|konas|(?<![a-z])boze(?![a-z])|coffee[\s_-]?client|jex[\s_-]?client|(?<![a-z])aoba(?![a-z])|argon[\s_-]?client|' +
    'doomsday|vape[\s_-]?(?:v4|lite|client)|novoline|sigma[\s_-]?(?:client|jello|5)|jello[\s_-]?client|rise[\s_-]?client|' +
    'tenacity[\s_-]?client|fdp[\s_-]?client|nursultan|wexside|celestial[\s_-]?client|expensive[\s_-]?client|' +
    'rockstar[\s_-]?client|inertia[\s_-]?client|wolfram[\s_-]?client|huzuni|(?<![a-z])nodus(?![a-z])|skill[\s_-]?client|' +
    'flare[\s_-]?client|prestige[\s_-]?client|krypton[\s_-]?client|lambda[\s_-]?client|raven[\s_-]?(?:b\+|bplus|bs|xd)|' +
    'wurst[\s_-]?plus|(?<![a-z])oyvey|gamesense[\s_-]?client|baritone|hacked[\s_-]?client|cheat[\s_-]?client|ghost[\s_-]?client|' +
    'kill[\s_-]?aura|auto[\s_-]?clicker|trigger[\s_-]?bot|aim[\s_-]?(?:assist|bot)|(?<![a-z])x[\s_-]?ray(?![a-z]))'), $RxOpt)

# Names that are cheat clients too, but are also ordinary words. On their own
# they make a jar SUSPICIOUS rather than CHEAT. "prestige" lives here.
$LooseCheatNameRx = [regex]::new(('(?<![a-z])(?:prestige|argon|raven|sigma|astolfo|exhibition|augustus|vestige|tenacity|' +
    'whiteout|slinky|koid|akrien|gamesense|xulu|catlean|phobos|salhack|novoline|moon[\s_-]?client|drip[\s_-]?(?:client|lite)|' +
    'vape|cheats?|hack(?:s|ed)?|aimbot|blatant|ghostclient)(?![a-z])'), $RxOpt)

# Extra words that only count when they show up in the Minecraft window title.
$CheatTitleRx = [regex]::new('\b(?:meteor|impact|future|sigma|rise|novoline|tenacity|fdp|exhibition|astolfo|raven|vape|prestige|argon|augustus|vestige)\b', $RxOpt)

# Mods that are not cheat clients but give an edge most servers do not allow.
$UtilityRx = [regex]::new(('(?:free[\s_-]?cam|(?<![a-z])x[\s_-]?ray|seed[\s_-]?crack|tweakeroo|litematica[\s_-]?printer|' +
    'elytra[\s_-]?(?:auto[\s_-]?pilot|fly)|auto[\s_-]?(?:fish|totem|armou?r|eat|mine|attack|clicker)|chest[\s_-]?esp|' +
    'entity[\s_-]?radar|crystal[\s_-]?optimi[sz]er|free[\s_-]?look|inventory[\s_-]?walk)'), $RxOpt)

# Known-bad files by SHA-1 (add samples of private clients here, or put
# "<sha1> <name>" lines in %APPDATA%\ZoreInspector\signatures.txt or in the
# file / URL named by the ZORE_SIGNATURES environment variable).
$KnownBadHashes = @{
    # '0123456789abcdef0123456789abcdef01234567' = 'Example: Prestige Client 1.x'
}

# --- Cheat modules ------------------------------------------------------------
# Class names are compared after stripping Module/Hack/Mod/Feature/Cheat
# affixes (ModuleKillAura, KillauraHack, KillAuraModule -> KillAura).

# Always a cheat module, wherever the class sits.
$StrongClass = @{}
foreach ($n in @(
    # combat
    'KillAura', 'AimAssist', 'AimBot', 'SilentAim', 'TriggerBot', 'AutoClicker', 'LeftClicker', 'RightClicker',
    'TPAura', 'InfiniteAura', 'MultiAura', 'LegitAura', 'SilentAura', 'AntiKnockback', 'NoKnockback', 'Criticals',
    'BowAimbot', 'BowSpam', 'FastBow', 'TargetStrafe', 'AutoPot', 'AutoSoup', 'AntiBot', 'WTap', 'STap', 'HitSelect',
    'FakeLag', 'Backtrack', 'PingSpoof', 'TickBase', 'ShieldBreaker', 'ShieldDisabler', 'AutoMace', 'MaceSwap',
    'AttributeSwap', 'BreachSwap', 'StunSlam', 'JumpReset', 'AutoJumpReset', 'AntiAim', 'Spinbot',
    # crystal / anchor / totem PvP (ghost-client staples)
    'CrystalAura', 'AutoCrystal', 'AutoHitCrystal', 'HitCrystal', 'CrystalMacro', 'AnchorAura', 'AutoAnchor',
    'AnchorMacro', 'BedAura', 'AutoDoubleHand', 'DoubleHand', 'AutoTotem', 'OffhandTotem', 'HoverTotem',
    'InventoryTotem', 'AutoInventoryTotem', 'LegitTotem', 'TotemMacro', 'KeyPearl', 'PearlCatch', 'PistonAura',
    'CevBreaker', 'AutoTrap', 'SelfTrap', 'HoleFiller', 'AutoCity',
    # movement
    'Scaffold', 'ScaffoldWalk', 'ElytraFly', 'PacketFly', 'BoatFly', 'EntityFly', 'EntitySpeed', 'CreativeFly',
    'FlyHack', 'SpeedHack', 'NoFall', 'NoSlow', 'NoSlowdown', 'InfiniteJump', 'Bhop', 'BunnyHop', 'VClip', 'HClip',
    # render
    'ClickGUI', 'XRay', 'ESP', 'StorageESP', 'PlayerESP', 'ChestESP', 'ItemESP', 'MobESP', 'EntityESP', 'HoleESP',
    'BlockESP', 'Chams', 'Wallhack',
    # world / player / exploits
    'Nuker', 'ChestStealer', 'PacketMine', 'InstantMine', 'InstaBreak', 'SpeedMine', 'GhostHand', 'XCarry',
    'AutoDupe', 'PortalGodMode', 'BookCrash', 'ServerCrasher', 'SelfDestruct', 'InvCleaner', 'InvManager'
)) { $StrongClass[$n] = $n }

# Usually a cheat module; strong when it sits in a modules/hacks/cheats folder.
$WeakClass = @{}
foreach ($n in @(
    'Reach', 'HitBoxes', 'Hitbox', 'AutoArmor', 'FastPlace', 'FastBreak', 'FastUse', 'Tracers', 'Freecam', 'Jesus',
    'Surround', 'Burrow', 'AutoWeapon', 'AutoSword', 'AutoTool', 'AutoGapple', 'AutoEat', 'AutoFish', 'Flight', 'Fly',
    'Spider', 'Blink', 'Crasher', 'Disabler', 'NoClip', 'LongJump', 'HighJump', 'AirJump', 'SafeWalk', 'AntiVoid',
    'FastLadder', 'NoWeb', 'InventoryManager', 'InventoryCleaner', 'AntiHunger', 'NoRotate', 'SprintReset',
    'AutoBlock', 'ArrowDodge', 'AutoLog', 'AntiAFK', 'FakePlayer', 'Nametags', 'TrueSight', 'LogoutSpots',
    'NewChunks', 'Breadcrumbs', 'Trajectories', 'TargetHUD', 'HudEditor', 'Radar', 'Fullbright', 'NoRender',
    'AutoRespawn', 'ElytraFlight', 'Glide'
)) { $WeakClass[$n] = $n }

# Ordinary words that only count inside a modules/hacks/cheats folder.
$ContextClass = @{}
foreach ($n in @('Speed', 'Step', 'Timer', 'Velocity', 'Sprint', 'Phase', 'Sneak', 'Search', 'Zoom', 'NoHurtCam',
                 'CameraClip', 'Freelook', 'AutoWalk', 'AutoJump', 'Parkour', 'Notifier', 'Spammer', 'Derp')) { $ContextClass[$n] = $n }

$ModuleDirRx = [regex]::new('/(?:modules?|hacks?|cheats?)/', $RxFast)
$ModulePathRx = [regex]::new('/(?:modules?|hacks?|cheats?)/(?:combat|movement|render|visual|player|world|misc|exploits?|ghost|blatant|legit|crystal|pvp|client)/', $RxFast)

# Text that is searched for inside the class files of every jar that is not a
# known-good Modrinth file. All signatures are turned into plain lower-case
# keywords and found in ONE pass over the class bytes (a prefix-tree regex), so
# even 20 MB mods scan quickly.
#   L       keyword templates: ~ = optional separator (none / space / _ / -),
#           {a,b} = alternatives.  'kill~aura' -> killaura, kill aura, kill_aura ...
#   Before  the keyword must not have a letter right before it
#   After   'Lc' = no lower-case letter right after it (AutoTrap yes, autotrapdoor no)
#           'L'  = no letter at all right after it (creativeFly yes, creativeFlySpeed no)
# Every signature was checked against 80 popular legit mods. Words that legit
# mods use for their own features (elytraFly, holeFiller, autoAnchor, tickBase,
# dragClick, expandHitbox ...) are weak or left out.
$StringSigs = @(
    # combat
    @{ Name = 'KillAura';        Strong = $true;  L = 'kill~aura' }
    @{ Name = 'AimAssist';       Strong = $true;  L = 'aim~assist' }
    @{ Name = 'AimBot';          Strong = $true;  L = 'aim~bot' }
    @{ Name = 'SilentAim';       Strong = $true;  L = 'silent~{aim,rotation,rotations,swap}'; After = 'Lc' }
    @{ Name = 'TriggerBot';      Strong = $true;  L = 'trigger~bot' }
    @{ Name = 'AutoClicker';     Strong = $true;  L = '{auto,left,right}~clicker' }
    @{ Name = 'ClickPattern';    Strong = $true;  L = '{jitter,butterfly}~click' }
    @{ Name = 'Aura';            Strong = $true;  L = '{tp,infinite,legit,silent,multi,smooth,bed,anchor,piston}~aura' }
    @{ Name = 'AntiKnockback';   Strong = $true;  L = 'anti~knockback' }
    @{ Name = 'TargetStrafe';    Strong = $true;  L = 'target~strafe' }
    @{ Name = 'WTap';            Strong = $true;  L = 'w~tap'; Before = $true; After = 'L' }
    @{ Name = 'HitSelect';       Strong = $true;  L = 'hit~select'; After = 'L' }
    @{ Name = 'FakeLag';         Strong = $true;  L = 'fake~lag'; After = 'L' }
    @{ Name = 'PingSpoof';       Strong = $true;  L = 'ping~spoof' }
    @{ Name = 'ShieldBreaker';   Strong = $true;  L = 'shield~{breaker,disabler}' }
    @{ Name = 'MaceSwap';        Strong = $true;  L = @('auto~mace', '{mace,attribute,breach}~swap', 'stun~slam') }
    @{ Name = 'JumpReset';       Strong = $true;  L = 'jump~reset' }
    @{ Name = 'BowAimbot';       Strong = $true;  L = 'bow~{aimbot,spam}' }
    @{ Name = 'AutoSoup';        Strong = $true;  L = 'auto~soup' }
    @{ Name = 'SpinBot';         Strong = $true;  L = @('spin~bot', 'anti~aim'); After = 'Lc' }
    # crystal / anchor / totem PvP (what ghost clients like Prestige sell)
    @{ Name = 'CrystalAura';     Strong = $true;  L = @('crystal~aura', 'auto~hit~crystal') }
    @{ Name = 'AutoCrystal';     Strong = $true;  L = 'auto~crystal'; After = 'L' }
    @{ Name = 'AnchorMacro';     Strong = $true;  L = '{crystal,totem,pearl,anchor,pot,hit}~macro' }
    @{ Name = 'DoubleHand';      Strong = $true;  L = 'auto~double~hand' }
    @{ Name = 'AutoTotem';       Strong = $true;  L = @('auto~totem', '{hover,legit}~totem'); After = 'Lc' }
    @{ Name = 'KeyPearl';        Strong = $true;  L = @('key~pearl', 'pearl~catch') }
    @{ Name = 'CevBreaker';      Strong = $true;  L = 'cev~breaker' }
    # movement
    @{ Name = 'ScaffoldWalk';    Strong = $true;  L = 'scaffold~walk' }
    @{ Name = 'PacketFly';       Strong = $true;  L = 'packet~fly'; After = 'Lc' }
    @{ Name = 'BoatFly';         Strong = $true;  L = 'boat~fly'; After = 'Lc' }
    @{ Name = 'FlyHack';         Strong = $true;  L = '{fly,flight,speed}~hack' }
    @{ Name = 'GroundSpoof';     Strong = $true;  L = 'ground~spoof' }
    @{ Name = 'AntiCheatBypass'; Strong = $true;  After = 'Lc'
       L = '{grim,vulcan,verus,matrix,watchdog,ncp,nocheatplus,intave,karhu,spartan,aac,polar}~{fly,speed,disabler,bypass,velocity,nofall,scaffold,strafe,timer,step,jesus,phase}' }
    # render
    @{ Name = 'ClickGUI';        Strong = $true;  L = 'click~gui' }
    @{ Name = 'Wallhack';        Strong = $true;  L = 'wall~hack' }
    @{ Name = 'ESP';             Strong = $true;  L = '{storage,player,chest,item,mob,entity,hole,block,void,city,shulker,spawner}~esp'; After = 'Lc' }
    @{ Name = 'Chams';           Strong = $true;  L = 'chams'; Before = $true; After = 'Lc' }
    # world / exploits
    @{ Name = 'ChestStealer';    Strong = $true;  L = 'chest~stealer' }
    @{ Name = 'SpeedMine';       Strong = $true;  L = '{packet,instant,speed}~mine'; After = 'L' }
    @{ Name = 'XCarry';          Strong = $true;  L = 'x~carry'; Before = $true }
    @{ Name = 'Dupe';            Strong = $true;  L = @('auto~dupe', 'dupe~exploit') }
    @{ Name = 'Crasher';         Strong = $true;  L = @('book~crash', 'server~crasher', 'crash~exploit') }
    @{ Name = 'PortalGodMode';   Strong = $true;  L = 'portal~god' }
    @{ Name = 'HackedClient';    Strong = $true;  L = '{hacked,cheat,ghost,hack}~client' }
    # weaker hints - legit mods use these words too, so one alone means little
    @{ Name = 'ElytraFly';       Strong = $false; L = 'elytra~fly'; After = 'Lc' }
    @{ Name = 'GhostHand';       Strong = $false; L = 'ghost~hand' }
    @{ Name = 'HoleFiller';      Strong = $false; L = 'hole~filler' }
    @{ Name = 'AutoTrap';        Strong = $false; L = 'auto~trap'; After = 'Lc' }
    @{ Name = 'AutoAnchor';      Strong = $false; L = 'auto~anchor' }
    @{ Name = 'Nuker';           Strong = $false; L = 'nuker' }
    @{ Name = 'AutoPot';         Strong = $false; L = 'auto~pot'; After = 'Lc' }
    @{ Name = 'NoFall';          Strong = $false; L = 'no~fall'; After = 'Lc' }
    @{ Name = 'NoSlow';          Strong = $false; L = 'no~slow'; After = 'Lc' }
    @{ Name = 'NoKnockback';     Strong = $false; L = 'no~knockback' }
    @{ Name = 'Criticals';       Strong = $false; L = 'criticals'; After = 'Lc' }
    @{ Name = 'AntiBot';         Strong = $false; L = 'anti~bot'; After = 'Lc' }
    @{ Name = 'SelfDestruct';    Strong = $false; L = 'self~destruct' }
    @{ Name = 'XRay';            Strong = $false; L = 'x~ray'; Before = $true; After = 'Lc' }
    @{ Name = 'Freecam';         Strong = $false; L = 'free~cam'; After = 'Lc' }
    @{ Name = 'AutoArmor';       Strong = $false; L = 'auto~{armor,armour}' }
    @{ Name = 'FastPlace';       Strong = $false; L = 'fast~{place,break,use,bow}'; After = 'Lc' }
    @{ Name = 'Tracers';         Strong = $false; L = 'tracers'; After = 'Lc' }
    @{ Name = 'CPS';             Strong = $false; L = '{min,max}~cps' }
    @{ Name = 'Jump';            Strong = $false; L = '{long,high,air,infinite}~jump'; After = 'L' }
    @{ Name = 'BHop';            Strong = $false; L = @('b~hop', 'bunny~hop'); Before = $true }
    @{ Name = 'SafeWalk';        Strong = $false; L = 'safe~walk' }
    @{ Name = 'AntiVoid';        Strong = $false; L = 'anti~void' }
    @{ Name = 'Jesus';           Strong = $false; L = 'jesus'; Before = $true; After = 'Lc' }
    @{ Name = 'Fly';             Strong = $false; L = '{vanilla,motion,creative,jetpack,entity}~fly'; After = 'L' }
    @{ Name = 'AntiKick';        Strong = $false; L = 'anti~kick' }
    @{ Name = 'InvManager';      Strong = $false; L = '{inv,inventory}~{manager,cleaner}'; After = 'L' }
    @{ Name = 'SprintReset';     Strong = $false; L = 'sprint~reset' }
    @{ Name = 'ArrowDodge';      Strong = $false; L = 'arrow~dodge' }
    @{ Name = 'LogoutSpots';     Strong = $false; L = @('logout~spots', 'true~sight') }
    @{ Name = 'TargetHUD';       Strong = $false; L = @('target~hud', 'hud~editor') }
    @{ Name = 'Blatant';         Strong = $false; L = 'blatant'; Before = $true }
)
foreach ($sig in $StringSigs) { $sig.Kind = 'S' }

# What the code *does*. Only checked in a jar's own classes (not bundled
# libraries), because these calls are normal in big libraries.
$BehaviourSigs = @(
    @{ Name = 'DefineClass';  L = 'define{,hidden,anonymous}class'; After = 'Lc' }
    @{ Name = 'Crypto';       L = 'javax/crypto/{cipher,spec/secretkeyspec}' }
    @{ Name = 'Network';      L = @('java/net/{httpurlconnection,urlconnection,http/httpclient}', 'okhttp3/') }
    @{ Name = 'Network';      L = 'java/net/socket'; After = 'Lc' }
    @{ Name = 'Instrument';   L = @('java/lang/instrument/', 'com/sun/tools/attach/', 'jdk/attach') }
    @{ Name = 'NativeLoad';   L = 'loadlibrary' }
    @{ Name = 'Hwid';         L = 'hwid'; Before = $true; After = 'Lc' }
    @{ Name = 'Hwid';         L = @('wmic {csproduct,bios,cpu,diskdrive,baseboard}', 'machineguid') }
    @{ Name = 'Webhook';      L = 'discord{,app}.com/api/webhooks' }
    @{ Name = 'StealDiscord'; L = @('local storage{\,/}leveldb', 'discord{,canary,ptb}{\,/}local storage') }
    @{ Name = 'StealBrowser'; L = @('login data', 'encrypted_key', 'web data{\,/}', 'cookies{\,/}network') }
    @{ Name = 'StealMc';      L = @('launcher_accounts{,_microsoft_store}.json', '.feather{\,/}accounts', 'lunarclient{\,/}settings{\,/}game{\,/}accounts', 'microsoft_accounts.json', 'tlauncher_profiles') }
    @{ Name = 'StealWallet';  L = @('wallet.dat', 'exodus{\,/}exodus', 'atomic{\,/}local storage', 'electrum{\,/}wallets', 'telegram desktop{\,/}tdata') }
    @{ Name = 'AntiSS';       L = @('anydesk', 'teamviewer', 'echo.ac', 'ocean.ac', 'paladin.ac', 'screen~share', 'process~hacker', 'systeminformer', 'lastactivityview', 'bam~parser', 'usbdeview', 'everything.exe') }
    @{ Name = 'AntiSS';       L = @('echoac', 'ss~tool'); Before = $true; After = 'L' }
    @{ Name = 'Robot';        L = 'java/awt/robot' }
    @{ Name = 'MousePress';   L = @('mousepress', 'mouserelease') }
    @{ Name = 'WinInput';     L = @('mouse_event', 'keybd_event', 'getasynckeystate', 'setwindowshookex') }
    @{ Name = 'WinInput';     L = 'sendinput'; After = 'L' }
    @{ Name = 'ClickInvoker'; L = '{invoke,call}{doattack,doitemuse,handleblockbreaking,startattack,startuseitem,continueattack}' }
    @{ Name = 'Obfuscator';   L = 'allatorixdemo' }
    @{ Name = 'Obfuscator';   L = '{allatori,zelix,klassmaster,skidfuscator,branchlock,paramorphism,superblaze,binsecure,qprotect,bozar}'; Before = $true; After = 'L' }
    @{ Name = 'Obfuscator';   L = 'obfuscated~{by,with}'; After = 'L' }
    @{ Name = 'NativeObf';    L = @('jnicloader', 'native~obfuscator') }
    @{ Name = 'NativeObf';    L = @('jnic', 'j2cc'); Before = $true; After = 'Lc' }
)
foreach ($sig in $BehaviourSigs) { $sig.Kind = 'B' }

# Uses the API of a cheat client -> addon / plugin.
$ApiSigs = @(foreach ($k in @($CheatApis.Keys)) { @{ Name = $CheatApis[$k]; Kind = 'A'; L = $k } })

# keyword templates -> keywords
function Expand-Template([string]$T) {
    $i = $T.IndexOf('{')
    if ($i -ge 0) {
        $j = $T.IndexOf('}', $i)
        $out = @()
        foreach ($opt in $T.Substring($i + 1, $j - $i - 1).Split(',')) { $out += @(Expand-Template ($T.Substring(0, $i) + $opt + $T.Substring($j + 1))) }
        return $out
    }
    $i = $T.IndexOf('~')
    if ($i -ge 0) {
        $out = @()
        foreach ($sep in @('', ' ', '_', '-')) { $out += @(Expand-Template ($T.Substring(0, $i) + $sep + $T.Substring($i + 1))) }
        return $out
    }
    return @($T)
}

# keywords -> one prefix-tree regex (fast even on .NET Framework / PowerShell 5.1)
function Get-TriePattern([string[]]$Words) {
    $groups = [ordered]@{}
    $optional = $false
    foreach ($w in $Words) {
        if ($w.Length -eq 0) { $optional = $true; continue }
        $c = $w.Substring(0, 1)
        if (-not $groups.Contains($c)) { $groups[$c] = New-Object System.Collections.Generic.List[string] }
        $groups[$c].Add($w.Substring(1))
    }
    if ($groups.Count -eq 0) { return '' }
    $alts = @(foreach ($c in @($groups.Keys)) { [regex]::Escape($c) + (Get-TriePattern $groups[$c].ToArray()) })
    if ($alts.Count -eq 1 -and -not $optional) { return $alts[0] }
    $p = '(?:' + ($alts -join '|') + ')'
    if ($optional) { $p += '?' }
    return $p
}

$KeywordMap = @{}   # keyword -> signatures that use it
foreach ($sig in @($StringSigs) + @($BehaviourSigs) + @($ApiSigs)) {
    foreach ($t in @($sig.L)) {
        foreach ($w in @(Expand-Template $t.ToLowerInvariant())) {
            if (-not $KeywordMap.ContainsKey($w)) { $KeywordMap[$w] = New-Object System.Collections.Generic.List[object] }
            $KeywordMap[$w].Add($sig)
        }
    }
}
$Keywords    = [string[]]@($KeywordMap.Keys)
$KeywordSigs = New-Object object[] $Keywords.Length
$KeywordIndex = @{}
for ($k = 0; $k -lt $Keywords.Length; $k++) { $KeywordSigs[$k] = $KeywordMap[$Keywords[$k]]; $KeywordIndex[$Keywords[$k]] = $k }

# Fast keyword search: a tiny Aho-Corasick matcher (one linear pass over the raw
# class bytes, ASCII case-insensitive). Compiled once per PowerShell session.
# If Add-Type is not allowed, a slower regex prefix tree is used instead.
$AhoSource = @'
using System;
using System.Collections.Generic;
public sealed class ZoreAhoV2 {
    private readonly int[] next; private readonly int[][] outs; private readonly int[] lens;
    private readonly int[] cmap = new int[256]; private readonly int alpha;
    public ZoreAhoV2(string[] words) {
        for (int i = 0; i < 256; i++) cmap[i] = -1;
        int a = 0;
        foreach (string w in words) foreach (char c in w) {
            if (c < 256 && cmap[c] < 0) {
                cmap[c] = a;
                char up = Char.ToUpperInvariant(c);
                if (up < 256 && up != c) cmap[up] = a;
                a++;
            }
        }
        alpha = a;
        List<int[]> go = new List<int[]>(); List<List<int>> o = new List<List<int>>();
        go.Add(Row()); o.Add(new List<int>());
        lens = new int[words.Length];
        for (int k = 0; k < words.Length; k++) {
            int s = 0; lens[k] = words[k].Length;
            foreach (char c in words[k]) {
                int ci = cmap[c];
                if (go[s][ci] < 0) { go[s][ci] = go.Count; go.Add(Row()); o.Add(new List<int>()); }
                s = go[s][ci];
            }
            o[s].Add(k);
        }
        int n = go.Count; next = new int[n * alpha]; int[] fail = new int[n];
        Queue<int> q = new Queue<int>();
        for (int c = 0; c < alpha; c++) { int t = go[0][c]; if (t < 0) next[c] = 0; else { next[c] = t; q.Enqueue(t); } }
        while (q.Count > 0) {
            int s = q.Dequeue();
            o[s].AddRange(o[fail[s]]);
            for (int c = 0; c < alpha; c++) {
                int t = go[s][c];
                if (t < 0) next[s * alpha + c] = next[fail[s] * alpha + c];
                else { next[s * alpha + c] = t; fail[t] = next[fail[s] * alpha + c]; q.Enqueue(t); }
            }
        }
        outs = new int[n][]; for (int i = 0; i < n; i++) outs[i] = o[i].ToArray();
    }
    private int[] Row() { int[] r = new int[alpha]; for (int i = 0; i < alpha; i++) r[i] = -1; return r; }
    // returns pairs: start index, keyword index
    public int[] Find(byte[] data, int length) {
        List<int> hits = new List<int>(); int s = 0;
        for (int i = 0; i < length; i++) {
            int ci = cmap[data[i]];
            if (ci < 0) { s = 0; continue; }
            s = next[s * alpha + ci];
            int[] hit = outs[s];
            for (int j = 0; j < hit.Length; j++) { hits.Add(i - lens[hit[j]] + 1); hits.Add(hit[j]); }
        }
        return hits.ToArray();
    }
}
'@
$AhoScanner = $null
try {
    if (-not ('ZoreAhoV2' -as [type])) { Add-Type -TypeDefinition $AhoSource -Language CSharp -ErrorAction Stop }
    $AhoScanner = New-Object ZoreAhoV2 (, $Keywords)
} catch { $AhoScanner = $null }
$KeywordRx = $null
if (-not $AhoScanner) {
    $KeywordRx = [regex]::new((Get-TriePattern @($Keywords | Sort-Object -Property Length -Descending)), [System.Text.RegularExpressions.RegexOptions]'CultureInvariant')
}

# File types that are compressed already, so an incompressible one is normal.
$PackedExtRx = [regex]::new('\.(?:png|jpe?g|gif|webp|ico|icns|ogg|oga|mp3|m4a|flac|opus|mp4|webm|zip|jar|gz|tgz|xz|lz4|zst|bz2|br|7z|rar|nbt|dat|mca|mcr|schem|schematic|litematic|nbs|woff2?|ttf|otf|pack|idx|class)$', $RxOpt)
# File types a zip archive / Windows program may legitimately be stored as.
$ArchiveExtRx = [regex]::new('\.(?:jar|zip|mcpack|mrpack|mcaddon|mcworld|xpi|apk|litemod|nupkg)$', $RxOpt)
$TextExtRx    = [regex]::new('\.(?:json|json5|txt|mcmeta|lang|toml|properties|cfg|conf|snbt|mcfunction|glsl|vsh|fsh|gsh|csh|frag|vert|comp|csv|md|html?|css|js|xml|ya?ml|kts?|java|accesswidener|classtweaker|refmap|nbtx|svg|ini|sql)$', $RxOpt)
$ProgramExtRx = [regex]::new('\.(?:exe|dll|sys|ocx|cpl|scr|efi|mui)$', $RxOpt)

# A jar named like a popular mod must actually contain that mod.
$DisguiseMap = [ordered]@{
    'sodium'            = 'sodium'
    'lithium'           = 'lithium'
    'iris'              = 'iris'
    'fabric-api'        = 'fabric'
    'modmenu'           = 'modmenu'
    'optifabric'        = 'optifabric'
    'optifine'          = 'optifine'
    'ferritecore'       = 'ferritecore'
    'entityculling'     = 'entityculling'
    'krypton'           = 'krypton'
    'cloth-config'      = 'cloth'
    'architectury'      = 'architectury'
    'appleskin'         = 'appleskin'
    'journeymap'        = 'journeymap'
    'xaero'             = 'xaero'
    'voicechat'         = 'voicechat'
    'zoomify'           = 'zoomify'
    'immediatelyfast'   = 'immediatelyfast'
    'continuity'        = 'continuity'
    'lambdynamiclights' = 'lambdynlights|lambdynamiclights'
    'dynamic-fps'       = 'dynamic_fps|dynamicfps'
    'distanthorizons'   = 'distanthorizons'
    'replaymod'         = 'replaymod'
    'worldedit'         = 'worldedit'
    'modernfix'         = 'modernfix'
    'indium'            = 'indium'
    'fabric-language-kotlin' = 'fabric(?:_|-)language(?:_|-)kotlin'
    'jei'               = 'jei'
}

# Data folders that cheat clients create (relative to the game folder).
$TraceFolders = [ordered]@{
    'meteor-client'      = 'Meteor Client'
    'wurst'              = 'Wurst Client'
    'LiquidBounce'       = 'LiquidBounce'
    'Impact'             = 'Impact'
    'Future'             = 'Future Client'
    'rusherhack'         = 'RusherHack'
    'kamiblue'           = 'KAMI Blue'
    'lambda'             = 'Lambda'
    'SalHack'            = 'SalHack'
    'phobos'             = 'Phobos'
    'earthhack'          = '3arthh4ck'
    'Konas'              = 'Konas'
    'ThunderHack'        = 'ThunderHack'
    'ThunderHackRecode'  = 'ThunderHack'
    'bleach'             = 'BleachHack'
    'boze'               = 'Boze'
    'baritone'           = 'Baritone'
    'libraries\EMC'      = 'Aristois (EMC)'
}
$HomeTraceFolders = [ordered]@{ 'Future' = 'Future Client'; '.weave' = 'Weave loader (injects mods into Lunar Client)' }

# Any folder/file in the game folder, its config folder or the user's AppData
# that is named exactly like a cheat client (Prestige, Argon, Vape, ...).
$ClientFolderRx = [regex]::new(('^\.?(?:prestige|argon|doomsday|vape|vapelite|drip|whiteout|slinky|koid|akrien|raven|ravenb\+|' +
    'sigma|rise|astolfo|exhibition|augustus|vestige|tenacity|novoline|nursultan|celestial|wexside|meteor-client|meteorclient|' +
    'wurst|liquidbounce|aristois|rusherhack|thunderhack|boze|bleachhack|gamesense|oyvey|wurstplus|xulu|mio|catlean|' +
    'cheats?|hacks?|ghostclient)(?:[\s_.-]?(?:client|config|configs|cfg|loader|data|v?\d+(?:\.\d+)*))?(?:\.(?:json|txt|cfg|dat|toml|yml))?$'), $RxOpt)
$ClientFolderStrictRx = [regex]::new('^\.?(?:prestige(?:client)?|argonclient|doomsday(?:client)?|vape(?:lite|v4)?|drip(?:client|lite)?|whiteout|slinky|koid|akrien|ravenb\+|meteor-client|liquidbounce|rusherhack|thunderhack|nursultan|wexside|ghostclient)$', $RxOpt)

$CheatSiteRx  = [regex]::new('(?:meteorclient\.com|wurstclient\.net|liquidbounce\.net|ccbluex|aristois\.net|impactclient\.net|futureclient\.net|rusherhack\.org|bleachhack\.org|boze\.dev|vape\.gg|doomsdayclient|novoline|sigmaclient|riseclient|nursultan|wexside|thunderhack|prestigeclient|prestige\.(?:gg|cc|wtf|vip|dev|lol)|argonclient)', $RxOpt)
$FileHostRx   = [regex]::new('(?:mediafire\.com|mega\.nz|mega\.io|gofile\.io|anonfiles|pixeldrain\.com|cdn\.discordapp\.com|media\.discordapp\.net|dropbox\.com|drive\.google\.com|filebin|transfer\.sh|wetransfer|we\.tl|sendspace|krakenfiles|catbox\.moe|uploadhaven|4shared|bunkr)', $RxOpt)

$CheatLoaderRx = [regex]::new('^(?:vape|drip|slinky|koid|whiteout|akrien|doomsday|entropyclient|prestige)(?:[\s_.-]*(?:v?\d[\w.]*|client|loader|launcher|lite|injector|x64|x86))*$', $RxOpt)
$ClickerRx     = [regex]::new('(?:auto[\s_-]?click|clicker|op[\s_-]?auto|gs[\s_-]?auto|tiny[\s_-]?task|macro[\s_-]?recorder|jitbit|pulover|keyran|mouse[\s_-]?recorder|speed[\s_-]?click)', $RxOpt)
$InjectorRx    = [regex]::new('(?:injector|cheat[\s_-]?engine|cheatengine|xenos|extreme[\s_-]?inj|dll[\s_-]?inj|process[\s_-]?inject)', $RxOpt)
$ReviewProcRx  = [regex]::new('^(?:autohotkey(?:u64|u32|64|32)?|ahk|processhacker|systeminformer|x64dbg|x32dbg|ollydbg|recaf|bytecode[\s_-]?viewer|jd-gui|luyten)$', $RxOpt)
$ReviewTitleRx = [regex]::new('(?:recaf|bytecode viewer|jd-gui|luyten|process hacker|system informer|cheat engine)', $RxOpt)
$BenignAgentRx = [regex]::new('(?:lunar|feather|badlion|labymod|essential|ichor|yourkit|jprofiler|async-profiler|newrelic|idea_rt|debugger-agent|jacoco)', $RxOpt)
$McCommandRx   = [regex]::new('(?:net\.minecraft|--gameDir|minecraft\.launcher|fabricmc|minecraftforge|neoforged|quiltmc|lunar|--accessToken|--assetIndex|prismlauncher|multimc|launchwrapper)', $RxOpt)

# DLLs that the game legitimately loads from user folders (LWJGL natives, JNA, voice chat, ...).
$NativeAllowRx = [regex]::new('^(?:lwjgl|glfw|openal|jemalloc|jinput|jna|discord|sqlite|netty|zstd|lz4|snappy|opus|libopus|rnnoise|speex|tinyfd|nfd|vulkan|shaderc|jcef|libcef|chrome_elf|icu|avcodec|avformat|avutil|avfilter|avdevice|swscale|swresample|oshi|jnativehook|mcef|webview|imgui|lunar|feather|badlion|essential|libsodium|zlib|vcruntime|msvcp|concrt|ucrtbase|api-ms-win-)[^\\/]*\.dll$', $RxOpt)
# Native libraries legit mods commonly bundle.
$KnownNativeRx = [regex]::new('(?:lwjgl|glfw|openal|jemalloc|jna|discord|sqlite|netty|zstd|lz4|snappy|opus|rnnoise|speex|libsodium|jcef|mcef|imgui|oshi|jnativehook|zlib|brotli|conscrypt|bouncycastle|lmdb|rocksdb|leveldb|jssc|hid4java|libusb|sdl|steam_api|libvlc|ffmpeg|av(?:codec|format|util)|nvidium|vulkan)', $RxOpt)
$UserDropDirRx = [regex]::new('\\(?:temp|tmp|downloads|desktop)\\', $RxOpt)

$JarLikeRx = [regex]::new('\.(?:jar|jar\.disabled|litemod|zip)$', $RxOpt)
$ExecRx    = [regex]::new('\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|msi|com|sys)$', $RxOpt)

$SevRank  = @{ MALWARE = 4; CHEAT = 3; SUSPICIOUS = 2; REVIEW = 1; INFO = 0; CLEAN = 0 }
$SevColor = @{ MALWARE = 'Red'; CHEAT = 'Red'; SUSPICIOUS = 'Yellow'; REVIEW = 'Magenta'; INFO = 'Cyan'; CLEAN = 'Green'; VERIFIED = 'Green'; UNKNOWN = 'DarkGray' }
$KindLabel = @{ Mod = 'mod'; ExtraMod = 'loaded from outside the mods folder'; Agent = 'Java agent'; GameJar = 'game jar' }

# =============================================================================
#  Output (everything printed after the banner is also kept for the report)
# =============================================================================
$Z = @{
    Report   = New-Object System.Collections.Generic.List[string]
    Line     = ''
    Findings = New-Object System.Collections.Generic.List[object]
    NoProgress = $false
    MemNotes = New-Object System.Collections.Generic.List[string]
}
try { $Z.NoProgress = [Console]::IsOutputRedirected } catch { }

function Out-Part([string]$Text, [string]$Color = 'Gray') {
    if (-not $Color) { $Color = 'Gray' }
    Write-Host $Text -ForegroundColor $Color -NoNewline
    $Z.Line += $Text
}

function Out-Row([string]$Text = '', [string]$Color = 'Gray') {
    if (-not $Color) { $Color = 'Gray' }
    Write-Host $Text -ForegroundColor $Color
    $Z.Report.Add($Z.Line + $Text)
    $Z.Line = ''
}

function Out-Tag([string]$Tag) {
    $color = $SevColor[$Tag]
    if (-not $color) { $color = 'Gray' }
    Out-Part '  '
    Out-Part (('[' + $Tag + ']').PadRight(13)) $color
}

function Out-Detail([string]$Text, [string]$Color = 'DarkGray') {
    Out-Row ((' ' * 15) + $Text) $Color
}

function Out-Section([string]$Title) {
    Out-Row ''
    Out-Part ('  ' + $Ch.Heavy + $Ch.Heavy + ' ') 'Blue'
    Out-Part $Title 'White'
    Out-Row (' ' + ($Ch.Heavy * [Math]::Max(4, 72 - $Title.Length))) 'Blue'
}

function Out-Phase([int]$Number, [string]$Text) {
    Out-Part ('  [' + $Number + '/6] ') 'Cyan'
    Out-Row $Text 'White'
}

function Out-Done([string]$Text, [string]$Color = 'DarkGray') {
    Out-Row ('        ' + $Text) $Color
}

function Add-Finding([string]$Severity, [string]$Area, [string]$Title, [string]$Detail = '') {
    $Z.Findings.Add([pscustomobject]@{ Severity = $Severity; Area = $Area; Title = $Title; Detail = $Detail })
}

function Get-ConsoleWidth {
    $w = 0
    try { $w = $Host.UI.RawUI.WindowSize.Width } catch { }
    if (-not $w -or $w -lt 40) { $w = 120 }
    return $w
}

function Show-Progress([int]$Index, [int]$Total, [string]$Name) {
    if ($Z.NoProgress) { return }
    $w = (Get-ConsoleWidth) - 1
    $t = ('        [' + $Index + '/' + $Total + '] ' + $Name)
    if ($t.Length -gt $w) { $t = $t.Substring(0, $w) }
    Write-Host ("`r" + $t.PadRight($w)) -NoNewline -ForegroundColor DarkGray
}

function Clear-Progress {
    if ($Z.NoProgress) { return }
    $w = (Get-ConsoleWidth) - 1
    Write-Host ("`r" + (' ' * $w) + "`r") -NoNewline
}

# =============================================================================
#  Banner
# =============================================================================
function Write-ArtLine([string]$Line) {
    $sb  = New-Object System.Text.StringBuilder
    $cur = 'Cyan'
    foreach ($c in $Line.ToCharArray()) {
        $s = [string]$c
        if ($s -eq ' ') { [void]$sb.Append(' '); continue }
        $col = 'DarkCyan'
        if ($s -eq '#') { $col = 'Cyan' }
        $out = $ArtMap[$s]
        if (-not $out) { $out = $s }
        if ($col -ne $cur -and $sb.Length -gt 0) {
            Write-Host $sb.ToString() -ForegroundColor $cur -NoNewline
            [void]$sb.Clear()
        }
        $cur = $col
        [void]$sb.Append($out)
    }
    if ($sb.Length -gt 0) { Write-Host $sb.ToString() -ForegroundColor $cur -NoNewline }
    Write-Host ''
}

function Show-Banner {
    try { Clear-Host } catch { }
    $w = Get-ConsoleWidth
    Write-Host ''
    Write-Host '  Tip: Run PowerShell as Administrator for the deepest scan. Looks best in Windows Terminal.' -ForegroundColor Yellow
    Write-Host ''
    if ($w -ge 88) {
        foreach ($l in $BannerArt) { Write-ArtLine ('  ' + $l) }
    } else {
        Write-Host '  Z O R E   C L I E N T   I N S P E C T O R' -ForegroundColor Cyan
    }
    Write-Host ''
    foreach ($l in $Mascot) { Write-Host $l -ForegroundColor Cyan }
    Write-Host ''
    Write-Host '                             Made with ' -ForegroundColor White -NoNewline
    Write-Host $Ch.Heart -ForegroundColor Red -NoNewline
    Write-Host ' by ' -ForegroundColor White -NoNewline
    Write-Host $ZoreCredit -ForegroundColor Cyan -NoNewline
    Write-Host ('   v' + $ZoreVersion) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host ($Ch.Heavy * [Math]::Min(88, $w - 1)) -ForegroundColor Blue
    Write-Host ''
}

# =============================================================================
#  Small helpers
# =============================================================================
function Get-Match([string]$Text, [string]$Pattern) {
    $m = [regex]::Match($Text, $Pattern)
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Join-Where([string]$Where, [string]$What) {
    if ($Where) { return ($What + '  (inside ' + $Where + ')') }
    return $What
}

function Join-Limited($Items, [int]$Max) {
    $arr  = @($Items)
    $text = (@($arr | Select-Object -First $Max)) -join ', '
    if ($arr.Count -gt $Max) { $text += (' (+' + ($arr.Count - $Max) + ' more)') }
    return $text
}

function Get-PrintableText([string]$Text) {
    return ($Text -replace '[^\x20-\x7E]', ' ')
}

function Test-SamePath([string]$A, [string]$B) {
    if (-not $A -or -not $B) { return $false }
    try {
        $A = [IO.Path]::GetFullPath($A).TrimEnd('\', '/')
        $B = [IO.Path]::GetFullPath($B).TrimEnd('\', '/')
    } catch { }
    return [string]::Equals($A, $B, [StringComparison]::OrdinalIgnoreCase)
}

function Get-Sha1([string]$Path) {
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
    try {
        $sha = [System.Security.Cryptography.SHA1]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    } finally { $fs.Dispose() }
}

function Get-DownloadSource([string]$Path) {
    # Windows remembers where a downloaded file came from in the
    # Zone.Identifier alternate data stream.
    if (-not $IsWin) { return $null }
    try {
        $url = $null; $ref = $null
        foreach ($l in @(Get-Content -LiteralPath $Path -Stream 'Zone.Identifier' -ErrorAction Stop)) {
            if ($l -like 'HostUrl=*') { $url = $l.Substring(8) }
            elseif ($l -like 'ReferrerUrl=*') { $ref = $l.Substring(12) }
        }
        if ($url -or $ref) { return @{ Url = $url; Referrer = $ref } }
    } catch { }
    return $null
}

# Value of "--name value" / "--name "value"" in a command line.
function Get-CmdArg([string]$Cmd, [string]$Name) {
    $m = [regex]::Match($Cmd, '(?:^|\s)' + [regex]::Escape($Name) + '\s+(?:"([^"]*)"|(\S+))')
    if (-not $m.Success) { return $null }
    if ($m.Groups[1].Success) { return $m.Groups[1].Value }
    return $m.Groups[2].Value
}

# Every value of "-prefixVALUE", "-prefix"VALUE"" or ""-prefixVALUE"".
function Get-PrefixedValues([string]$Cmd, [string]$Prefix) {
    $e = [regex]::Escape($Prefix)
    $out = @()
    foreach ($m in [regex]::Matches($Cmd, ('"' + $e + '([^"]*)"|' + $e + '(?:"([^"]*)"|([^\s"]+))'))) {
        for ($g = 1; $g -le 3; $g++) {
            if ($m.Groups[$g].Success) { $out += $m.Groups[$g].Value; break }
        }
    }
    return $out
}

# =============================================================================
#  Finding the running game
# =============================================================================
function Find-InstanceDir([string]$Cmd) {
    # Prism / MultiMC do not pass --gameDir, but their paths contain \instances\<name>\
    $m = [regex]::Match($Cmd, '(?i)[a-z]:\\(?:[^"\\;=:]+\\)*?instances\\[^\\";=:]+')
    if ($m.Success -and (Test-Path -LiteralPath $m.Value)) {
        foreach ($sub in @('.minecraft', 'minecraft')) {
            $cand = Join-Path $m.Value $sub
            if (Test-Path -LiteralPath $cand) { return $cand }
        }
        return $m.Value
    }
    $m = [regex]::Match($Cmd, '(?i)[a-z]:\\(?:[^"\\;=:]+\\)*?\.minecraft(?=\\|"|;|\s|$)')
    if ($m.Success) { return $m.Value }
    return $null
}

function Read-Instance($Proc) {
    $cmd    = [string]$Proc.CommandLine
    $procId = [int]$Proc.ProcessId
    $exe    = [string]$Proc.ExecutablePath

    $start = $null
    try {
        if ($Proc.CreationDate -is [datetime]) { $start = $Proc.CreationDate }
        elseif ($Proc.CreationDate) { $start = [System.Management.ManagementDateTimeConverter]::ToDateTime($Proc.CreationDate) }
    } catch { }
    $title = ''
    try {
        $gp = Get-Process -Id $procId -ErrorAction Stop
        $title = [string]$gp.MainWindowTitle
        if (-not $start) { $start = $gp.StartTime }
    } catch { }

    $javaHome = $null
    if ($exe) { $javaHome = Split-Path (Split-Path $exe -Parent) -Parent }

    $gameDir = Get-CmdArg $cmd '--gameDir'
    if (-not $gameDir -and $cmd) { $gameDir = Find-InstanceDir $cmd }
    $modsDir = $null
    if ($gameDir) { $modsDir = Join-Path $gameDir 'mods' }

    $loader = 'Vanilla'
    if     ($cmd -match '(?i)lunar')                         { $loader = 'Lunar Client' }
    elseif ($cmd -match '(?i)badlion')                       { $loader = 'Badlion Client' }
    elseif ($cmd -match '(?i)feather')                       { $loader = 'Feather Client' }
    elseif ($cmd -match '(?i)labymod')                       { $loader = 'LabyMod' }
    elseif ($cmd -match '(?i)quiltmc')                       { $loader = 'Quilt' }
    elseif ($cmd -match '(?i)fabricmc|fabric-loader')        { $loader = 'Fabric' }
    elseif ($cmd -match '(?i)neoforge')                      { $loader = 'NeoForge' }
    elseif ($cmd -match '(?i)minecraftforge|fmlloader|forge') { $loader = 'Forge' }
    elseif ($cmd -match '(?i)optifine')                      { $loader = 'OptiFine' }

    $cp = Get-CmdArg $cmd '-cp'
    if (-not $cp) { $cp = Get-CmdArg $cmd '-classpath' }
    if (-not $cp) { $cp = @(Get-PrefixedValues $cmd '-Djava.class.path=') | Select-Object -First 1 }
    $classPath = @()
    if ($cp) { $classPath = @($cp -split ';' | Where-Object { $_ }) }

    $brand = @(Get-PrefixedValues $cmd '-Dminecraft.launcher.brand=') | Select-Object -First 1

    return @{
        Pid       = $procId
        Exe       = $exe
        Cmd       = $cmd
        Limited   = (-not $cmd)
        Start     = $start
        Title     = $title
        JavaHome  = $javaHome
        GameDir   = $gameDir
        ModsDir   = $modsDir
        Loader    = $loader
        VersionId = (Get-CmdArg $cmd '--version')
        Brand     = $brand
        Agents    = @(Get-PrefixedValues $cmd '-javaagent:' | ForEach-Object {
                        $i = $_.ToLowerInvariant().IndexOf('.jar')
                        if ($i -gt 0) { $_.Substring(0, $i + 4) } else { $_ } })
        AddMods   = @(Get-PrefixedValues $cmd '-Dfabric.addMods=')
        NativeAgents = @(@(Get-PrefixedValues $cmd '-agentpath:' | ForEach-Object { 'agentpath:' + $_ }) +
                         @(Get-PrefixedValues $cmd '-agentlib:'  | ForEach-Object { 'agentlib:' + $_ }) +
                         @(Get-PrefixedValues $cmd '-Xrun'       | ForEach-Object { 'agentlib:' + $_ }))
        ModuleBases = @()
        ClassPath = $classPath
    }
}

function Get-MinecraftInstances {
    $found = New-Object System.Collections.Generic.List[object]
    if (-not $IsWin) { return ,$found }
    $filter = "Name='javaw.exe' OR Name='java.exe'"
    $procs = @()
    try { $procs = @(Get-CimInstance -ClassName Win32_Process -Filter $filter -ErrorAction Stop) }
    catch {
        try { $procs = @(Get-WmiObject -Class Win32_Process -Filter $filter -ErrorAction Stop) } catch { $procs = @() }
    }
    foreach ($p in $procs) {
        $cmd = [string]$p.CommandLine
        if ($cmd -and -not $McCommandRx.IsMatch($cmd)) { continue }   # some other Java program
        if ($cmd -match '(?i)(?:^|\s)-{0,2}nogui(?:\s|$)') { continue } # a server, not a client
        $found.Add((Read-Instance $p))
    }
    return ,$found
}

function Show-Instances($Instances) {
    if ($Instances.Count -eq 0) {
        Write-Host '  No running Minecraft instance found.' -ForegroundColor Yellow
        Write-Host '  Start the game first to include the live checks (window, java agents, injected DLLs).' -ForegroundColor DarkGray
        return
    }
    foreach ($i in $Instances) {
        Write-Host '  [LIVE] ' -ForegroundColor Green -NoNewline
        Write-Host ('Minecraft is running  -  PID ' + $i.Pid + '  -  ' + $i.Loader + '  ' + $i.VersionId) -ForegroundColor White
        if ($i.Title)   { Write-Host ('         Window : ' + $i.Title) -ForegroundColor DarkGray }
        if ($i.GameDir) { Write-Host ('         Folder : ' + $i.GameDir) -ForegroundColor DarkGray }
        if ($i.Limited) { Write-Host '         (could not read its details - run as Administrator)' -ForegroundColor DarkYellow }
    }
}

# =============================================================================
#  Live game checks
# =============================================================================
function Test-LoadedModules($Inst) {
    $area = 'Minecraft PID ' + $Inst.Pid
    $mods = @()
    try { $mods = @((Get-Process -Id $Inst.Pid -ErrorAction Stop).Modules) } catch { }
    if ($mods.Count -eq 0) {
        Add-Finding 'INFO' $area 'Could not list the DLLs loaded into the game' 'Run 64-bit PowerShell as Administrator for the DLL injection check.'
        return
    }
    $Inst.ModuleBases = @($mods | ForEach-Object { try { $_.BaseAddress.ToInt64() } catch { } })
    $loaded = @{}
    foreach ($m in $mods) { if ($m.FileName) { $loaded[[IO.Path]::GetFileName([string]$m.FileName)] = [string]$m.FileName } }

    # instrument.dll = a Java agent is running inside the game. Without -javaagent
    # at launch, something attached it while the game was running.
    if ($loaded.ContainsKey('instrument.dll') -and @($Inst.Agents | Where-Object { $_ }).Count -eq 0) {
        Add-Finding 'SUSPICIOUS' $area 'A Java agent was attached to the game while it was running' ('instrument.dll is loaded but the game was not started with -javaagent. Injected clients do this; a few mods attach themselves too. ' + $loaded['instrument.dll'])
    }
    if ($loaded.ContainsKey('attach.dll')) {
        Add-Finding 'REVIEW' $area 'The game uses the Java attach API' ('attach.dll is loaded - code in the game can attach agents to a JVM. ' + $loaded['attach.dll'])
    }

    $safe = @($env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $Inst.JavaHome) | Where-Object { $_ }
    foreach ($m in $mods) {
        $f = [string]$m.FileName
        if (-not $f) { continue }
        if (-not (Test-Path -LiteralPath $f)) {
            Add-Finding 'SUSPICIOUS' $area ('DLL loaded from a file that no longer exists: ' + [IO.Path]::GetFileName($f)) ($f + '   (deleted or moved after it was injected)')
            continue
        }
        $skip = $false
        foreach ($s in $safe) { if ($f.StartsWith($s, [StringComparison]::OrdinalIgnoreCase)) { $skip = $true; break } }
        if ($skip) { continue }
        $leaf = [IO.Path]::GetFileName($f)
        if ($NativeAllowRx.IsMatch($leaf)) { continue }
        $status = 'Unknown'
        try { $status = [string](Get-AuthenticodeSignature -LiteralPath $f -ErrorAction Stop).Status } catch { }
        if ($status -eq 'Valid') { continue }
        $sev = 'REVIEW'
        if ($UserDropDirRx.IsMatch($f)) { $sev = 'SUSPICIOUS' }
        if ($CheatNameRx.IsMatch($leaf)) { $sev = 'CHEAT' }
        Add-Finding $sev $area ('Unsigned DLL injected/loaded into the game: ' + $leaf) ($f + '  (signature: ' + $status + ')')
    }
}

function Test-VersionJar($Inst, [string]$Jar, [string]$VersionId, $Extra) {
    $area = 'Minecraft PID ' + $Inst.Pid
    $json = Join-Path (Split-Path $Jar -Parent) ($VersionId + '.json')
    $expected = $null
    if (Test-Path -LiteralPath $json) {
        try { $expected = [string](Get-Content -LiteralPath $json -Raw | ConvertFrom-Json).downloads.client.sha1 } catch { }
    }
    if ($expected) {
        $actual = $null
        try { $actual = Get-Sha1 $Jar } catch { }
        if ($actual -and $actual -ne $expected.ToLowerInvariant()) {
            Add-Finding 'SUSPICIOUS' $area ('The Minecraft game jar has been modified: ' + [IO.Path]::GetFileName($Jar)) ('SHA-1 ' + $actual + ' does not match the official ' + $expected)
            $Extra.Add(@{ Path = $Jar; Kind = 'GameJar' })
        } elseif ($actual) {
            Add-Finding 'INFO' $area ('Minecraft ' + $VersionId + ' game jar matches the official Mojang file') $Jar
        }
    } else {
        # Custom version (no official hash to compare with) - look inside it.
        $Extra.Add(@{ Path = $Jar; Kind = 'GameJar' })
    }
}

function Test-Instance($Inst, $Extra) {
    $area = 'Minecraft PID ' + $Inst.Pid
    if ($Inst.Limited) {
        Add-Finding 'REVIEW' $area 'Could not read the game command line' 'The game probably runs as Administrator - run this inspector as Administrator too.'
    }
    if ($Inst.Title) {
        $m = $CheatNameRx.Match($Inst.Title)
        if (-not $m.Success) { $m = $CheatTitleRx.Match($Inst.Title) }
        if ($m.Success) { Add-Finding 'CHEAT' $area 'The game window title shows a cheat client' ('Title: "' + $Inst.Title + '"') }
    }
    if ($Inst.VersionId -and $CheatNameRx.IsMatch($Inst.VersionId)) {
        Add-Finding 'CHEAT' $area ('The game was launched as a cheat client version: ' + $Inst.VersionId) '--version argument'
    }
    if ($Inst.Brand -and $CheatNameRx.IsMatch($Inst.Brand)) {
        Add-Finding 'CHEAT' $area ('Launched by a cheat client launcher: ' + $Inst.Brand) '-Dminecraft.launcher.brand'
    }

    foreach ($na in $Inst.NativeAgents) {
        $kind, $val = $na -split ':', 2
        $lib = $val
        $pm = [regex]::Match($val, '^(.*?\.(?:dll|so|dylib))(?:=.*)?$', 'IgnoreCase')
        if ($pm.Success) { $lib = $pm.Groups[1].Value } else { $lib = ($val -split '[=:,]', 2)[0] }
        $leaf = [IO.Path]::GetFileName($lib)
        $detail = '-' + $kind + ':' + $val
        if ($kind -eq 'agentpath' -and $IsWin -and (Test-Path -LiteralPath $lib -PathType Leaf)) {
            $st = 'Unknown'
            try { $st = [string](Get-AuthenticodeSignature -LiteralPath $lib -ErrorAction Stop).Status } catch { }
            $detail += '   (signature: ' + $st + ')'
        }
        if ($lib -match '(?i)^jdwp') {
            Add-Finding 'SUSPICIOUS' $area 'Java debugger (JDWP) is enabled - lets another program change game code while it runs' $detail
        } elseif ($CheatNameRx.IsMatch($val) -or $LooseCheatNameRx.IsMatch($leaf)) {
            Add-Finding 'CHEAT' $area ('Cheat injected as a native (JVMTI) agent: ' + $leaf) $detail
        } elseif ($lib -match '(?i)yjpagent|yourkit|jprofiler|asyncprofiler|async-profiler|hprof|jfr') {
            Add-Finding 'REVIEW' $area ('Profiler agent loaded into the game: ' + $leaf) $detail
        } else {
            Add-Finding 'SUSPICIOUS' $area ('Native (JVMTI) agent injected into the game: ' + $leaf) $detail
        }
    }
    if ($Inst.Cmd -match '(?i)-XX:\+EnableDynamicAgentLoading') {
        Add-Finding 'REVIEW' $area 'The game was started with agent attaching explicitly allowed (-XX:+EnableDynamicAgentLoading)' 'Lets an injector attach a Java agent while the game runs.'
    }
    if ($Inst.Cmd -match '(?i)-Djdk\.attach\.allowAttachSelf=true') {
        Add-Finding 'REVIEW' $area 'The game was started with self-attach allowed (-Djdk.attach.allowAttachSelf=true)' 'Lets code inside the game load a Java agent into itself.'
    }

    foreach ($a in $Inst.Agents) {
        if (-not $a) { continue }
        $leaf = [IO.Path]::GetFileName($a)
        if ($CheatNameRx.IsMatch($a)) {
            Add-Finding 'CHEAT' $area ('Cheat injected as a Java agent: ' + $leaf) $a
        } elseif ($a -match '(?i)authlib-injector') {
            Add-Finding 'REVIEW' $area 'authlib-injector Java agent (offline / cracked account system)' $a
        } elseif ($a -match '(?i)weave') {
            Add-Finding 'REVIEW' $area 'Weave loader Java agent (loads extra mods into Lunar Client)' $a
            $weaveMods = Join-Path (Join-Path $UserDir '.weave') 'mods'
            if (Test-Path -LiteralPath $weaveMods) {
                foreach ($j in @(Get-ChildItem -LiteralPath $weaveMods -Filter '*.jar' -File -Force -ErrorAction SilentlyContinue)) {
                    $Extra.Add(@{ Path = $j.FullName; Kind = 'ExtraMod' })
                }
            }
        } elseif ($BenignAgentRx.IsMatch($a)) {
            Add-Finding 'INFO' $area ('Java agent from a known client/launcher: ' + $leaf) $a
        } else {
            Add-Finding 'SUSPICIOUS' $area ('Unknown Java agent injected into the game: ' + $leaf) $a
        }
        if (Test-Path -LiteralPath $a -PathType Leaf) { $Extra.Add(@{ Path = $a; Kind = 'Agent' }) }
    }

    foreach ($am in $Inst.AddMods) {
        foreach ($p in @($am -split ';')) {
            $p = $p.Trim()
            if (-not $p) { continue }
            Add-Finding 'SUSPICIOUS' $area 'Extra mods are loaded from outside the mods folder (fabric.addMods)' $p
            if ($p.StartsWith('@')) { continue }
            if (Test-Path -LiteralPath $p -PathType Container) {
                foreach ($j in @(Get-ChildItem -LiteralPath $p -Filter '*.jar' -File -Force -ErrorAction SilentlyContinue)) {
                    $Extra.Add(@{ Path = $j.FullName; Kind = 'ExtraMod' })
                }
            } elseif (Test-Path -LiteralPath $p -PathType Leaf) {
                $Extra.Add(@{ Path = $p; Kind = 'ExtraMod' })
            }
        }
    }

    foreach ($cp in $Inst.ClassPath) {
        $leaf = [IO.Path]::GetFileName($cp)
        if ($CheatNameRx.IsMatch($leaf)) {
            Add-Finding 'CHEAT' $area ('Cheat jar on the game classpath: ' + $leaf) $cp
            if (Test-Path -LiteralPath $cp -PathType Leaf) { $Extra.Add(@{ Path = $cp; Kind = 'GameJar' }) }
            continue
        }
        $vm = [regex]::Match($cp, '(?i)[\\/]versions[\\/]([^\\/]+)[\\/][^\\/]+\.jar$')
        if ($vm.Success -and (Test-Path -LiteralPath $cp -PathType Leaf)) {
            Test-VersionJar $Inst $cp $vm.Groups[1].Value $Extra
        }
    }

    if (-not $Inst.Limited) { Test-LoadedModules $Inst }
}

# =============================================================================
#  Modrinth verification
# =============================================================================
function Get-ModrinthInfo([string[]]$Hashes) {
    $map = @{}
    $Hashes = @($Hashes | Where-Object { $_ } | Select-Object -Unique)
    if ($Hashes.Count -eq 0) { return @{ Map = $map; Online = $true } }

    $versions = @{}
    try {
        for ($i = 0; $i -lt $Hashes.Count; $i += 100) {
            $chunk = @($Hashes[$i..([Math]::Min($i + 99, $Hashes.Count - 1))])
            $body  = @{ hashes = $chunk; algorithm = 'sha1' } | ConvertTo-Json -Compress
            $resp  = Invoke-RestMethod -Method Post -Uri 'https://api.modrinth.com/v2/version_files' -Body $body `
                        -ContentType 'application/json' -UserAgent $UserAgent -TimeoutSec 20 -ErrorAction Stop
            if ($resp) { foreach ($p in $resp.PSObject.Properties) { $versions[$p.Name] = $p.Value } }
        }
    } catch {
        return @{ Map = $map; Online = $false; Error = $_.Exception.Message }
    }

    $titles = @{}
    $ids = @($versions.Values | ForEach-Object { $_.project_id } | Where-Object { $_ } | Select-Object -Unique)
    try {
        for ($i = 0; $i -lt $ids.Count; $i += 100) {
            $chunk = @($ids[$i..([Math]::Min($i + 99, $ids.Count - 1))])
            $json  = '[' + ((@($chunk | ForEach-Object { '"' + $_ + '"' })) -join ',') + ']'
            $projects = Invoke-RestMethod -Uri ('https://api.modrinth.com/v2/projects?ids=' + [uri]::EscapeDataString($json)) `
                            -UserAgent $UserAgent -TimeoutSec 20 -ErrorAction Stop
            foreach ($p in @($projects)) { $titles[[string]$p.id] = @{ Title = [string]$p.title; Slug = [string]$p.slug } }
        }
    } catch { }

    foreach ($h in @($versions.Keys)) {
        $v = $versions[$h]
        $t = $titles[[string]$v.project_id]
        $title = [string]$v.name; $slug = ''
        if ($t) { $title = $t.Title; $slug = $t.Slug }
        $map[$h] = @{ Title = $title; Slug = $slug; Version = [string]$v.version_number; ProjectId = [string]$v.project_id }
    }
    return @{ Map = $map; Online = $true }
}

# =============================================================================
#  Jar inspection
# =============================================================================
function New-JarResult([System.IO.FileInfo]$File, [string]$Kind) {
    return @{
        File = $File; Name = $File.Name; Path = $File.FullName; Kind = $Kind
        Sha1 = $null; Verified = $null; Source = $null; Referrer = $null; OpenError = $null
        ModId = $null; ModName = $null; ModVersion = $null; Loader = $null
        HasMeta = $false; IsOptiFine = $false; IsRusherPlugin = $false; Manifest = ''
        Depends = New-Object System.Collections.Generic.List[string]
        Entrypoints = New-Object System.Collections.Generic.List[string]
        Classes = 0; ShortNames = 0; WeirdNames = 0; Nested = 0
        BadMagic = 0; BadMagicWhere = $null; PackedClasses = 0; DupClasses = 0; FakeDirs = 0
        Known = @{}; Strong = @{}; Weak = @{}; ApiRefs = @{}; Behave = @{}; TextNames = @{}; ModulePath = $null
        Natives        = New-Object System.Collections.Generic.List[string]
        OwnNatives     = New-Object System.Collections.Generic.List[string]
        HiddenClasses  = New-Object System.Collections.Generic.List[string]
        HiddenArchives = New-Object System.Collections.Generic.List[string]
        HiddenPrograms = New-Object System.Collections.Generic.List[string]
        Blobs          = New-Object System.Collections.Generic.List[string]
        Reasons  = New-Object System.Collections.Generic.List[string]
        Evidence = New-Object System.Collections.Generic.List[string]
        Score = 0; Severity = 'CLEAN'; Deep = $false; IsMalware = $false
        Official = $null
    }
}

function Read-EntryBytes($Entry, [long]$Max) {
    if ($Entry.Length -gt $Max) { return $null }
    $s = $null
    try {
        $s  = $Entry.Open()
        $ms = New-Object System.IO.MemoryStream
        $s.CopyTo($ms)
        return ,$ms.ToArray()
    } catch { return $null }
    finally { if ($s) { $s.Dispose() } }
}

function Read-EntryText($Entry) {
    $b = Read-EntryBytes $Entry 4MB
    if ($null -eq $b) { return '' }
    return [System.Text.Encoding]::UTF8.GetString($b).TrimStart([char]0xFEFF)
}

function Add-JsonKeys($List, $Object) {
    if ($null -eq $Object) { return }
    foreach ($p in $Object.PSObject.Properties) { if ($p.Name) { $List.Add([string]$p.Name) } }
}

function Read-JsonMeta($R, [string]$Text, [string]$Loader) {
    $id = $null; $name = $null; $ver = $null; $j = $null
    if ($R.Loader -eq 'Forge' -or $R.Loader -eq 'NeoForge') { return }   # mods.toml wins over a stub fabric.mod.json
    $R.HasMeta = $true; $R.Loader = $Loader
    try { $j = ConvertFrom-Json -InputObject $Text -ErrorAction Stop } catch { $j = $null }
    if ($j) {
        if ($Loader -eq 'Quilt') {
            $id = $j.quilt_loader.id; $ver = $j.quilt_loader.version; $name = $j.quilt_loader.metadata.name
            foreach ($d in @($j.quilt_loader.depends)) {
                if ($d -is [string]) { $R.Depends.Add($d) } elseif ($d.id) { $R.Depends.Add([string]$d.id) }
            }
            Add-JsonKeys $R.Entrypoints $j.quilt_loader.entrypoints
        } else {
            $id = $j.id; $ver = $j.version; $name = $j.name
            Add-JsonKeys $R.Depends $j.depends
            Add-JsonKeys $R.Depends $j.recommends
            Add-JsonKeys $R.Depends $j.suggests
            Add-JsonKeys $R.Entrypoints $j.entrypoints
        }
    }
    if (-not $id)   { $id   = Get-Match $Text '"id"\s*:\s*"([^"]+)"' }
    if (-not $name) { $name = Get-Match $Text '"name"\s*:\s*"([^"]+)"' }
    if (-not $ver)  { $ver  = Get-Match $Text '"version"\s*:\s*"([^"]+)"' }
    $R.ModId = [string]$id; $R.ModName = [string]$name; $R.ModVersion = [string]$ver
}

function Read-TomlMeta($R, [string]$Text, [string]$Loader) {
    $R.HasMeta    = $true; $R.Loader = $Loader
    $ids = @([regex]::Matches($Text, '(?m)^\s*modId\s*=\s*["'']([^"'']+)["'']') | ForEach-Object { $_.Groups[1].Value })
    $R.ModId      = $ids | Select-Object -First 1
    foreach ($d in @($ids | Select-Object -Skip 1)) { $R.Depends.Add($d) }   # [[dependencies]] entries
    $R.ModName    = Get-Match $Text '(?m)^\s*displayName\s*=\s*["'']([^"'']+)["'']'
    $R.ModVersion = Get-Match $Text '(?m)^\s*version\s*=\s*["'']([^"'']+)["'']'
}

function Read-LegacyMeta($R, [string]$Text, [string]$Loader) {
    $R.HasMeta    = $true; $R.Loader = $Loader
    $R.ModId      = Get-Match $Text '(?i)"modid"\s*:\s*"([^"]+)"'
    $R.ModName    = Get-Match $Text '(?i)"name"\s*:\s*"([^"]+)"'
    $R.ModVersion = Get-Match $Text '(?i)"version"\s*:\s*"([^"]+)"'
    if (-not $R.ModId) { $R.ModId = $R.ModName }
}

function Read-YamlMeta($R, [string]$Text, [string]$Loader) {
    $R.HasMeta    = $true; $R.Loader = $Loader
    $R.ModName    = Get-Match $Text '(?m)^name\s*:\s*["'']?([^"''\r\n]+)'
    $R.ModVersion = Get-Match $Text '(?m)^version\s*:\s*["'']?([^"''\r\n]+)'
    $R.ModId      = $R.ModName
}

function Find-Keywords([byte[]]$Data, [int]$Length) {
    if ($AhoScanner) { return ,$AhoScanner.Find($Data, $Length) }
    $hits = New-Object System.Collections.Generic.List[int]
    foreach ($m in $KeywordRx.Matches($Latin1.GetString($Data, 0, $Length).ToLowerInvariant())) {
        $hits.Add($m.Index); $hits.Add($KeywordIndex[$m.Value])
    }
    return ,$hits.ToArray()
}

function Search-Buffer($R, [System.IO.MemoryStream]$Buffer, [string]$Where, [int]$Depth) {
    $data = $Buffer.GetBuffer()
    $len  = [int]$Buffer.Length
    $hits = Find-Keywords $data $len
    for ($h = 0; $h -lt $hits.Length; $h += 2) {
        $at   = $hits[$h]
        $k    = $hits[$h + 1]
        $word = $Keywords[$k]
        $end  = $at + $word.Length
        foreach ($sig in $KeywordSigs[$k]) {
            if ($sig.Kind -eq 'S') {
                if ($R.Verified) {
                    # Known-good Modrinth file: not scored, only remembered so the
                    # memory scan knows these words come from a jar on disk.
                    $R.TextNames[$sig.Name] = $true
                    continue
                }
                if ($R.Strong.ContainsKey($sig.Name) -or (-not $sig.Strong -and $R.Weak.ContainsKey($sig.Name))) { continue }
            } elseif ($sig.Kind -eq 'B') {
                if ($R.Verified -or $Depth -ne 0 -or $R.Behave.ContainsKey($sig.Name)) { continue }   # behaviour: the jar's own code only
            } elseif ($R.ApiRefs.ContainsKey($sig.Name)) { continue }
            if ($sig.Before -and $at -gt 0) {
                $b = $data[$at - 1]
                if (($b -ge 65 -and $b -le 90) -or ($b -ge 97 -and $b -le 122) -or $b -ge 192) { continue }
            }
            if ($sig.After -and $end -lt $len) {
                $b = $data[$end]
                if ($sig.After -eq 'L' -and (($b -ge 65 -and $b -le 90) -or ($b -ge 97 -and $b -le 122) -or $b -ge 192)) { continue }
                if ($sig.After -eq 'Lc' -and (($b -ge 97 -and $b -le 122) -or $b -ge 223)) { continue }
            }
            $found = Get-PrintableText $Latin1.GetString($data, $at, $word.Length)
            if ($sig.Kind -eq 'S') {
                $bucket = $R.Weak
                if ($sig.Strong) { $bucket = $R.Strong }
                $bucket[$sig.Name] = Join-Where $Where ("text '" + $found + "'")
            } elseif ($sig.Kind -eq 'B') {
                $R.Behave[$sig.Name] = $found
            } else {
                $R.ApiRefs[$sig.Name] = Join-Where $Where $found.TrimEnd('/').Replace('/', '.')
            }
        }
    }
}

function Read-ZipArchive($Zip, $R, [int]$Depth, [bool]$Deep, [string]$Where) {
    $buf   = $null
    $hdr   = New-Object byte[] 4
    $names = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($Deep) { $buf = New-Object System.IO.MemoryStream }
    try {
        foreach ($e in $Zip.Entries) {
            $full = $e.FullName
            if (-not $full) { continue }
            if ($full.EndsWith('/')) {
                # a folder called "Something.class/" hides code from naive scanners
                if ($Depth -eq 0 -and $full -like '*.class/') { $R.FakeDirs++ }
                continue
            }
            $lower = $full.ToLowerInvariant()
            $isClass = $lower.EndsWith('.class')
            if ($Depth -eq 0 -and -not $names.Add($full) -and $isClass) { $R.DupClasses++ }

            if ($isClass) {
                # 1. code from a known cheat client
                $m = $CheatPackageRx.Match($lower)
                if ($m.Success) {
                    $client = $CheatPackages[$m.Groups[1].Value]
                    if ($client -and -not $R.Known.ContainsKey($client)) {
                        $R.Known[$client] = Join-Where $Where ($m.Groups[1].Value.TrimEnd('/').Replace('/', '.'))
                    }
                }

                # 2. class names of cheat modules (KillAura.class, ModuleScaffold.class, KillauraHack.class...)
                $slash = $full.LastIndexOf('/')
                $base  = $full.Substring($slash + 1, $full.Length - $slash - 7)
                $dollar = $base.IndexOf('$')
                if ($dollar -gt 0) { $base = $base.Substring(0, $dollar) }
                if ($Depth -eq 0) {
                    $R.Classes++
                    if ($base.Length -le 2 -or $base -cmatch '^[Il1]{3,}$') { $R.ShortNames++ }
                    if ($base -match '[^A-Za-z0-9_$-]') { $R.WeirdNames++ }
                    if (-not $R.IsOptiFine -and $lower.StartsWith('net/optifine/')) { $R.IsOptiFine = $true }
                }
                # Real module classes are PascalCase; lower-case names are obfuscated
                # vanilla classes (Minecraft itself ships an "esp.class").
                $key = ''
                if ($base -cmatch '^[A-Z]') {
                    $key = $base -creplace '^(?:Module|Mod|Hack|Feature)(?=[A-Z])', '' -creplace '(?:Module|Hack|Mod|Feature|Cheat|Command|Cmd)$', ''
                }
                if ($key.Length -ge 3) {
                    $inModuleDir = $ModuleDirRx.IsMatch($lower)
                    $hit = $StrongClass[$key]
                    $strong = [bool]$hit
                    if (-not $hit) { $hit = $WeakClass[$key]; $strong = ($hit -and $inModuleDir) }
                    if (-not $hit -and $inModuleDir) { $hit = $ContextClass[$key] }
                    if ($hit) {
                        $bucket = $R.Weak
                        if ($strong) { $bucket = $R.Strong }
                        if (-not $bucket.ContainsKey($hit)) { $bucket[$hit] = Join-Where $Where ('class ' + $full) }
                    }
                }

                # 3. package layout of a hacked client
                if (-not $R.ModulePath -and $ModulePathRx.IsMatch($lower)) {
                    $R.ModulePath = Join-Where $Where ($full.Substring(0, [Math]::Max(0, $slash)))
                }

                # 4. the class bytes: encrypted classes, and text inside (module names survive renaming)
                if ($Deep -and $e.Length -le $MaxClassSize) {
                    $start = $buf.Length
                    $s = $null
                    try { $s = $e.Open(); $s.CopyTo($buf) } catch { } finally { if ($s) { $s.Dispose() } }
                    $a = $buf.GetBuffer()
                    if ($e.Length -ge 4 -and $buf.Length -ge $start + 4 -and
                        ($a[$start] -ne 0xCA -or $a[$start + 1] -ne 0xFE -or $a[$start + 2] -ne 0xBA -or $a[$start + 3] -ne 0xBE)) {
                        $R.BadMagic++
                        if (-not $R.BadMagicWhere) { $R.BadMagicWhere = Join-Where $Where $full }
                    } elseif ($e.Length -ge 2048 -and $e.CompressedLength -ne $e.Length -and $e.CompressedLength -ge [long]($e.Length * 0.95)) {
                        $R.PackedClasses++   # valid class whose body is random-looking data
                    }
                    $buf.WriteByte(10)
                    if ($buf.Length -ge $ChunkSize) { Search-Buffer $R $buf $Where $Depth; $buf.SetLength(0) }
                }
                continue
            }

            if ($Depth -eq 0) {
                if     ($lower -eq 'fabric.mod.json')             { Read-JsonMeta   $R (Read-EntryText $e) 'Fabric';         continue }
                elseif ($lower -eq 'quilt.mod.json')              { Read-JsonMeta   $R (Read-EntryText $e) 'Quilt';          continue }
                elseif ($lower -eq 'meta-inf/neoforge.mods.toml') { Read-TomlMeta   $R (Read-EntryText $e) 'NeoForge';       continue }
                elseif ($lower -eq 'meta-inf/mods.toml')          { Read-TomlMeta   $R (Read-EntryText $e) 'Forge';          continue }
                elseif ($lower -eq 'mcmod.info')                  { Read-LegacyMeta $R (Read-EntryText $e) 'Forge (legacy)'; continue }
                elseif ($lower -eq 'litemod.json')                { Read-LegacyMeta $R (Read-EntryText $e) 'LiteLoader';     continue }
                elseif ($lower -eq 'meta-inf/manifest.mf')        { $R.Manifest = Read-EntryText $e;                         continue }
                elseif ($lower -eq 'rusherhack-plugin.json')      { $R.IsRusherPlugin = $true; $R.HasMeta = $true;           continue }
                elseif ($lower -eq 'plugin.yml' -or $lower -eq 'paper-plugin.yml' -or $lower -eq 'bungee.yml') {
                    if (-not $R.HasMeta) { Read-YamlMeta $R (Read-EntryText $e) 'Server plugin (not loaded by the client)' }
                    continue
                }

                # Resources: classes, jars or programs hidden under another name,
                # and encrypted payloads (data that does not compress at all).
                if ($Deep -and $e.Length -ge 4 -and -not $TextExtRx.IsMatch($lower)) {
                    $isArchive = $ArchiveExtRx.IsMatch($lower)
                    $isProgram = $ProgramExtRx.IsMatch($lower)
                    $isNative  = $lower -match '\.(?:so|dylib|jnilib)$'
                    $n = 0; $s = $null
                    try { $s = $e.Open(); $n = $s.Read($hdr, 0, 4) } catch { } finally { if ($s) { $s.Dispose() } }
                    if ($n -ge 4) {
                        if ($hdr[0] -eq 0xCA -and $hdr[1] -eq 0xFE -and $hdr[2] -eq 0xBA -and $hdr[3] -eq 0xBE) {
                            # .class_manual / .class.bak style names are just renamed classes, not hidden ones
                            if (-not $isNative -and $lower -notmatch '\.class[^/]*$') { $R.HiddenClasses.Add($full) }
                        } elseif ($hdr[0] -eq 0x50 -and $hdr[1] -eq 0x4B -and $hdr[2] -eq 3 -and $hdr[3] -eq 4) {
                            if (-not $isArchive) { $R.HiddenArchives.Add($full) }
                        } elseif ($hdr[0] -eq 0x4D -and $hdr[1] -eq 0x5A) {
                            if (-not $isProgram -and -not $isNative) { $R.HiddenPrograms.Add($full) }
                        }
                    }
                    if ($e.Length -ge 32KB -and -not $isArchive -and -not $isProgram -and -not $PackedExtRx.IsMatch($lower) -and
                        $lower -notmatch '\.(?:so|dylib|jnilib)$' -and $e.CompressedLength -ne $e.Length -and $e.CompressedLength -ge [long]($e.Length * 0.97)) {
                        $R.Blobs.Add($full)
                    }
                }
            }

            if ($lower.EndsWith('.jar')) {
                # bundled jar-in-jar library: open it and scan it too
                if ($Deep -and $Depth -lt 2) {
                    $bytes = Read-EntryBytes $e $MaxNestedJar
                    if ($null -ne $bytes -and $bytes.Length -gt 0) {
                        $ms = New-Object System.IO.MemoryStream(, $bytes)
                        $nz = $null
                        try {
                            $nz = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Read, $false)
                            $R.Nested++
                            Read-ZipArchive -Zip $nz -R $R -Depth ($Depth + 1) -Deep $Deep -Where (Join-Where $Where $full)
                        } catch { } finally { if ($nz) { $nz.Dispose() }; $ms.Dispose() }
                    }
                }
                continue
            }

            if ($lower -match '\.(?:dll|exe|so|dylib|jnilib|sys)$') {
                $R.Natives.Add((Join-Where $Where $full))
                if ($Depth -eq 0 -and -not $KnownNativeRx.IsMatch($lower)) { $R.OwnNatives.Add($full) }
            }
        }
        if ($Deep -and $buf.Length -gt 0) { Search-Buffer $R $buf $Where $Depth }
    } finally {
        if ($buf) { $buf.Dispose() }
    }
}

function Invoke-JarScan($R, [bool]$Deep) {
    $fs = $null; $zip = $null
    try {
        $fs  = [System.IO.File]::Open($R.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read, $false)
    } catch {
        if ($fs) { $fs.Dispose() }
        $R.OpenError = $_.Exception.Message
        return
    }
    try {
        $R.Deep = ($Deep -and -not $R.Verified)
        Read-ZipArchive -Zip $zip -R $R -Depth 0 -Deep $Deep -Where ''
    } catch {
        $R.OpenError = $_.Exception.Message
    } finally {
        $zip.Dispose(); $fs.Dispose()
    }
}

# =============================================================================
#  Official-copy check: a jar that claims to be a Modrinth mod (by its mod id)
#  but is not one of its published files is compared with the real release.
# =============================================================================
function Get-NormName([string]$Text) { return ([string]$Text).ToLowerInvariant() -replace '[^a-z0-9]', '' }

# file name -> uncompressed size, for a jar on disk or in memory
function Get-ZipListing($Source) {
    $dict = New-Object 'System.Collections.Generic.Dictionary[string,long]' ([StringComparer]::Ordinal)
    $stream = $null; $zip = $null
    try {
        if ($Source -is [byte[]]) { $stream = New-Object System.IO.MemoryStream(, $Source) }
        else { $stream = [System.IO.File]::Open([string]$Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete') }
        $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        foreach ($e in $zip.Entries) {
            $n = $e.FullName
            if (-not $n -or $n.EndsWith('/')) { continue }
            if ($n -match '^META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))$') { continue }   # signatures / manifest differ between builds
            $dict[$n] = $e.Length
        }
    } catch { return $null }
    finally { if ($zip) { $zip.Dispose() }; if ($stream) { $stream.Dispose() } }
    return ,$dict
}

function Test-OfficialCopies($Results) {
    $cands = @($Results | Where-Object { -not $_.Verified -and ($_.Kind -eq 'Mod' -or $_.Kind -eq 'ExtraMod') -and $_.HasMeta -and $_.ModId -and $_.Sha1 -and $_.Known.Count -eq 0 })
    if ($cands.Count -eq 0) { return 0 }

    # 1. which claimed mod ids are real Modrinth projects (slug = mod id)
    $slugs = @{}
    foreach ($r in $cands) {
        $id = ([string]$r.ModId).ToLowerInvariant()
        foreach ($sl in @($id, $id.Replace('_', '-'))) { if ($sl -match '^[a-z0-9._-]{2,64}$') { $slugs[$sl] = $true } }
    }
    $projects = @{}
    try {
        $list = @($slugs.Keys)
        for ($i = 0; $i -lt $list.Count; $i += 100) {
            $chunk = @($list[$i..([Math]::Min($i + 99, $list.Count - 1))])
            $json  = '[' + ((@($chunk | ForEach-Object { '"' + $_ + '"' })) -join ',') + ']'
            $resp  = Invoke-RestMethod -Uri ('https://api.modrinth.com/v2/projects?ids=' + [uri]::EscapeDataString($json)) -UserAgent $UserAgent -TimeoutSec 20 -ErrorAction Stop
            foreach ($pr in @($resp)) { if ($pr.slug) { $projects[([string]$pr.slug).ToLowerInvariant()] = $pr } }
        }
    } catch { return 0 }

    $codeRx  = [regex]::new('\.(?:class|dll|exe|so|dylib|jnilib|sys)$', $RxOpt)
    $assetRx = [regex]::new('\.(?:png|jpe?g|gif|webp|ogg|json|json5|txt|lang|mcmeta|toml|properties|nbt|snbt|ttf|otf|md|cfg|fsh|vsh|glsl|accesswidener|classtweaker|jar)$', $RxOpt)
    $downloaded = 0L; $checked = 0; $compared = 0
    foreach ($r in $cands) {
        $id = ([string]$r.ModId).ToLowerInvariant()
        $pr = $projects[$id]
        if (-not $pr) { $pr = $projects[$id.Replace('_', '-')] }
        if (-not $pr) { continue }
        # same slug can belong to an unrelated project: the names must agree too
        $t = Get-NormName $pr.title; $n = Get-NormName $r.ModName; $nid = Get-NormName $r.ModId
        $nameMatch = ($t -eq $n -or ($n.Length -ge 4 -and ($t.Contains($n) -or $n.Contains($t))))
        if (-not ($nameMatch -or $t -eq $nid)) { continue }

        if ($checked -ge 40) { continue }   # limit API calls; unchecked jars are simply not judged here
        $checked++
        $versions = @()
        try {
            # assign first: Invoke-RestMethod returns a JSON array as ONE object, so @(irm ...) would nest it
            $resp = Invoke-RestMethod -Uri ('https://api.modrinth.com/v2/project/' + $pr.id + '/version') -UserAgent $UserAgent -TimeoutSec 20 -ErrorAction Stop
            $versions = @($resp)
        } catch { continue }
        if ($versions.Count -eq 0) { continue }
        $r.Official = @{ Status = 'Unofficial'; Title = [string]$pr.title; Slug = [string]$pr.slug; Version = $null; Added = @(); Changed = @(); Removed = @(); NameMatch = $nameMatch }

        # 2. the official file this jar pretends to be: same file name, else same version
        $myName = ($r.Name -replace '(?i)\.disabled$', '' -replace '\s*\(\d+\)(?=\.jar$)', '').ToLowerInvariant()
        $match = $null; $matchVer = $null
        foreach ($v in $versions) {
            foreach ($f in @($v.files)) { if (([string]$f.filename).ToLowerInvariant() -eq $myName) { $match = $f; $matchVer = $v; break } }
            if ($match) { break }
        }
        if (-not $match -and $r.ModVersion) {
            $loader = ([string]$r.Loader).ToLowerInvariant()
            foreach ($v in $versions) {
                $vn = [string]$v.version_number
                if ($vn -ne $r.ModVersion -and $vn -notmatch ('(?<![0-9.])' + [regex]::Escape([string]$r.ModVersion) + '(?![0-9])')) { continue }
                if (@('fabric', 'quilt', 'forge', 'neoforge') -contains $loader -and @($v.loaders) -notcontains $loader) { continue }
                $match = @($v.files | Where-Object { $_.primary }) | Select-Object -First 1
                if (-not $match) { $match = @($v.files) | Select-Object -First 1 }
                $matchVer = $v
                break
            }
        }
        if (-not $match) { continue }
        $r.Official.Version = [string]$matchVer.version_number
        $r.Official.File = [string]$match.filename
        $r.Official.Status = 'Mismatch'

        # 3. download the official file and compare the contents
        if ([long]$match.size -gt 64MB -or ($downloaded + [long]$match.size) -gt 300MB) { continue }
        $bytes = $null; $wc = $null
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers['User-Agent'] = $UserAgent
            $bytes = $wc.DownloadData([string]$match.url)
            $downloaded += $bytes.Length
        } catch { continue } finally { if ($wc) { $wc.Dispose() } }
        $off  = Get-ZipListing $bytes
        $mine = Get-ZipListing $r.Path
        if ($null -eq $off -or $null -eq $mine) { continue }
        $compared++
        $added = @(); $changed = @(); $removed = @()
        foreach ($k in $mine.Keys) {
            if (-not $off.ContainsKey($k)) { $added += $k }
            elseif ($off[$k] -ne $mine[$k]) { $changed += $k }
        }
        foreach ($k in $off.Keys) { if (-not $mine.ContainsKey($k)) { $removed += $k } }
        $r.Official.Added = $added; $r.Official.Changed = $changed; $r.Official.Removed = $removed
        $codeAdded   = @($added   | Where-Object { $codeRx.IsMatch($_) -or -not $assetRx.IsMatch($_) })
        $codeChanged = @($changed | Where-Object { $codeRx.IsMatch($_) })
        if ($codeAdded.Count -gt 0 -or $codeChanged.Count -gt 0) {
            $r.Official.Status = 'Tampered'
            $r.Official.Code = @($codeAdded) + @($codeChanged)
        } elseif ($added.Count + $changed.Count + $removed.Count -gt 0) {
            $r.Official.Status = 'Modified'
        } else {
            $r.Official.Status = 'Repacked'   # same files, only re-zipped
        }
    }
    return $compared
}

function Add-Reason($R, [int]$Points, [string]$Why) {
    $R.Score += $Points
    $R.Reasons.Add($Why)
}

function Measure-JarResult($R, $GameStart) {
    if ($R.ModVersion -match '\$\{') {
        $R.ModVersion = Get-Match $R.Manifest '(?im)^Implementation-Version\s*:\s*(\S+)'
    }
    $isMod    = ($R.Kind -eq 'Mod' -or $R.Kind -eq 'ExtraMod')
    $verified = [bool]$R.Verified
    $B        = $R.Behave

    if ($R.OpenError -and $R.Kind -ne 'GameJar') {
        Add-Reason $R 15 'Not a readable jar (renamed, corrupted or locked file)'
    }

    # --- known files and known clients ---------------------------------------
    if ($R.Sha1 -and $KnownBadHashes.ContainsKey($R.Sha1)) {
        Add-Reason $R 100 ('Exact match with a known cheat file: ' + $KnownBadHashes[$R.Sha1])
    }
    foreach ($client in @($R.Known.Keys)) {
        Add-Reason $R 100 ('Contains code of the cheat client ' + $client)
        $R.Evidence.Add($R.Known[$client])
    }

    $addonOf = New-Object System.Collections.Generic.List[string]
    foreach ($d in $R.Depends) {
        if ($d -ne $R.ModId -and $CheatModIds.ContainsKey($d) -and -not $addonOf.Contains($CheatModIds[$d])) { $addonOf.Add($CheatModIds[$d]) }
    }
    if ($R.Entrypoints -contains 'meteor' -and -not $addonOf.Contains('Meteor Client')) { $addonOf.Add('Meteor Client') }
    if ($R.IsRusherPlugin -and -not $addonOf.Contains('RusherHack')) { $addonOf.Add('RusherHack') }
    if ($R.Known.Count -eq 0) {
        foreach ($c in @($R.ApiRefs.Keys)) { if (-not $addonOf.Contains($c)) { $addonOf.Add($c); $R.Evidence.Add('uses ' + $R.ApiRefs[$c]) } }
    }
    if ($addonOf.Count -gt 0) { Add-Reason $R 80 ('Addon / plugin for the cheat client ' + ($addonOf -join ', ')) }

    $names = @($R.Name, $R.ModId, $R.ModName) | Where-Object { $_ }
    if (-not $verified) {
        $named = $false
        foreach ($n in $names) {
            $m = $CheatNameRx.Match($n)
            if ($m.Success) { Add-Reason $R 60 ("Name matches a cheat client / cheat feature: '" + $m.Value + "'"); $named = $true; break }
        }
        if (-not $named) {
            foreach ($n in $names) {
                $m = $LooseCheatNameRx.Match($n)
                if ($m.Success) { Add-Reason $R 35 ("Name looks like a cheat client: '" + $m.Value + "'"); break }
            }
        }
        if ($R.ModId -and $CheatModIds.ContainsKey($R.ModId)) {
            Add-Reason $R 80 ("Mod id '" + $R.ModId + "' belongs to " + $CheatModIds[$R.ModId])
        }
    } else {
        $vText = (@($R.Verified.Title, $R.Verified.Slug, $R.ModId) | Where-Object { $_ }) -join ' '
        $m = $CheatNameRx.Match($vText)
        if ($m.Success) { Add-Reason $R 30 ("Published on Modrinth, but it is a cheat-type mod ('" + $m.Value + "')") }
    }

    # --- claims to be an official mod, but is not its published file ---------
    $o = $R.Official
    if ($o -and -not $verified) {
        $what = $o.Title
        if ($o.Version) { $what += ' ' + $o.Version }
        $diff = @()
        if ($o.Added.Count)   { $diff += ([string]$o.Added.Count + ' file(s) added') }
        if ($o.Changed.Count) { $diff += ([string]$o.Changed.Count + ' changed') }
        if ($o.Removed.Count) { $diff += ([string]$o.Removed.Count + ' removed') }
        if ($o.Status -eq 'Tampered') {
            Add-Reason $R 45 ('Tampered copy of the official ' + $what + ' from Modrinth: ' + ($diff -join ', ') + ' - code that is not in the real mod: ' + (Join-Limited $o.Code 4))
        } elseif ($o.Status -eq 'Modified') {
            Add-Reason $R 15 ('Modified copy of the official ' + $what + ' from Modrinth (' + ($diff -join ', ') + '): ' + (Join-Limited (@($o.Added) + @($o.Changed) + @($o.Removed)) 4))
        } elseif ($o.Status -eq 'Mismatch') {
            Add-Reason $R 10 ('Same name / version as the official ' + $what + ' (' + $o.File + ') on Modrinth, but different contents (not compared)')
        } elseif ($o.Status -eq 'Unofficial' -and $o.NameMatch) {
            # weak on its own (CurseForge builds, ports under another project) - context only
            Add-Reason $R 0 ('Claims to be ' + $o.Title + ' (modrinth.com/mod/' + $o.Slug + ') but is not any official release - fine if it came from CurseForge or a dev build')
        } elseif ($o.Status -eq 'Unofficial') {
            Add-Reason $R 10 ("Uses the mod id '" + $R.ModId + "' of " + $o.Title + ' (modrinth.com/mod/' + $o.Slug + ') but is a different mod')
        }
    }

    # --- cheat modules ---------------------------------------------------------
    foreach ($k in @($R.Strong.Keys)) { if ($R.Weak.ContainsKey($k)) { $R.Weak.Remove($k) } }
    $sc = $R.Strong.Count
    if ($sc -gt 0) {
        Add-Reason $R ([Math]::Min(75, 15 * $sc)) ('Cheat modules found (' + $sc + '): ' + (Join-Limited (@($R.Strong.Keys) | Sort-Object) 12))
        foreach ($k in @(@($R.Strong.Keys) | Sort-Object | Select-Object -First 3)) { $R.Evidence.Add($k + ' -> ' + $R.Strong[$k]) }
    }
    $wc = $R.Weak.Count
    if ($wc -gt 0) {
        # Huge legit mods mention lots of words; weak hits count less there.
        $per = 4
        if ($sc -eq 0 -and $R.Classes -ge 800) { $per = 2 }
        Add-Reason $R ([Math]::Min(20, $per * $wc)) ('Cheat-like feature names (' + $wc + '): ' + (Join-Limited (@($R.Weak.Keys) | Sort-Object) 12))
    }
    if (-not $verified -and $R.ModulePath) { Add-Reason $R 8 ('Hacked-client package layout: ' + $R.ModulePath) }

    # --- hiding tricks (what paid / ghost clients do to survive a scan) ---------
    if (-not $verified -and $R.Kind -ne 'GameJar') {
        if ($R.Classes -ge 25) {
            $ratio = $R.ShortNames / $R.Classes
            if ($ratio -ge 0.5) {
                Add-Reason $R 20 ('Heavily obfuscated: ' + [int]($ratio * 100) + '% of ' + $R.Classes + ' classes have 1-2 letter names (legit mods almost never do this)')
            }
        }
        if ($R.WeirdNames -ge 5) { Add-Reason $R 15 ($R.WeirdNames.ToString() + ' class names use hidden or invalid characters') }
    }
    if (-not $verified) {
        if ($R.BadMagic -gt 0) {
            Add-Reason $R 35 ([string]$R.BadMagic + ' .class file(s) are encrypted / not real Java classes - the code is only revealed at runtime')
            $R.Evidence.Add('encrypted class: ' + $R.BadMagicWhere)
        }
        if ($R.PackedClasses -ge 2) { Add-Reason $R 20 ([string]$R.PackedClasses + ' classes are full of random-looking data (encrypted strings or payload)') }
        if ($R.HiddenClasses.Count -gt 0)  { Add-Reason $R 35 ('Java classes hidden under other file names: ' + (Join-Limited $R.HiddenClasses 3)) }
        if ($R.HiddenArchives.Count -gt 0) { Add-Reason $R 20 ('Jar/zip archives hidden under other file names: ' + (Join-Limited $R.HiddenArchives 3)) }
        if ($R.HiddenPrograms.Count -gt 0) { Add-Reason $R 25 ('Windows programs hidden under other file names: ' + (Join-Limited $R.HiddenPrograms 3)) }
        if ($R.Blobs.Count -gt 0)          { Add-Reason $R 15 ('Encrypted / packed data files: ' + (Join-Limited $R.Blobs 3)) }
        if ($R.DupClasses -gt 0)           { Add-Reason $R 15 ([string]$R.DupClasses + ' duplicate class entries (zip trick to hide code from scanners)') }
        if ($R.FakeDirs -gt 0)             { Add-Reason $R 15 ([string]$R.FakeDirs + ' folders disguised as .class files (anti-decompiler trick)') }
    }

    # --- behaviour of the jar's own code ---------------------------------------
    # Loading code at runtime / instrumentation are normal in some big legit
    # mods, so they only count when the jar also hides its code.
    $hides = ($R.BadMagic -gt 0 -or $R.HiddenClasses.Count -gt 0 -or $R.HiddenArchives.Count -gt 0 -or $R.Blobs.Count -gt 0 -or
              $B.Obfuscator -or $B.NativeObf -or ($R.Classes -ge 25 -and ($R.ShortNames / $R.Classes) -ge 0.5))
    if (-not $verified) {
        if ($R.Manifest -match '(?im)^(?:Obfuscated-By|Protected-By|Obfuscator)\s*:|allatori|zelix|skidfuscator|branchlock|paramorphism|superblaze|binsecure|qprotect|bozar') {
            if (-not $B.ContainsKey('Obfuscator')) { $B['Obfuscator'] = 'manifest' }
        }
        if ($hides -and $B.DefineClass -and ($B.Crypto -or $B.Network)) {
            $how = @()
            if ($B.Crypto)  { $how += 'decrypts' }
            if ($B.Network) { $how += 'downloads' }
            Add-Reason $R 30 ('Loader behaviour: ' + ($how -join ' / ') + ' code and defines classes at runtime (how cheat loaders hide the real client)')
        }
        if ($hides -and $B.Instrument -and $R.Kind -ne 'Agent') { Add-Reason $R 20 'Uses the Java instrumentation / attach API to rewrite the game while it runs' }
        if ($B.Hwid) { Add-Reason $R 25 ("Reads a hardware ID ('" + $B.Hwid + "') - license lock used by paid cheat clients") }

        $steal = @()
        if ($B.StealDiscord) { $steal += 'Discord tokens' }
        if ($B.StealBrowser) { $steal += 'browser passwords/cookies' }
        if ($B.StealMc)      { $steal += 'Minecraft accounts' }
        if ($B.StealWallet)  { $steal += 'crypto wallets / Telegram' }
        if (($B.Webhook -and $steal.Count -ge 1) -or $steal.Count -ge 2) {
            $R.IsMalware = $true
            Add-Reason $R 100 ('MALWARE - steals ' + ($steal -join ', ') + $(if ($B.Webhook) { ' and sends them to a Discord webhook' } else { '' }))
        } elseif ($B.Webhook) {
            Add-Reason $R 25 'Sends data to a Discord webhook (common in account stealers)'
        } elseif ($steal.Count -eq 1) {
            Add-Reason $R 8 ('Reads ' + $steal[0] + ' files')
        }

        if ($B.AntiSS) { Add-Reason $R 30 ("Looks for screenshare tools ('" + $B.AntiSS + "') - anti-screenshare / self-destruct trick") }
        if (($B.Robot -and $B.MousePress) -or $B.WinInput) { Add-Reason $R 25 'Simulates real mouse / keyboard input (auto-clicker / macro)' }
        if ($B.ClickInvoker) { Add-Reason $R 6 ("Triggers attack / use clicks from code ('" + $B.ClickInvoker + "') - triggerbot / autoclicker behaviour (controller mods do this too)") }
        if ($B.Obfuscator) { Add-Reason $R 25 ("Protected by a Java obfuscator ('" + $B.Obfuscator + "') - legit mods publish readable code") }
        if ($B.NativeObf) { Add-Reason $R 30 ("Code converted to native machine code ('" + $B.NativeObf + "') - used by paid ghost clients") }
        elseif ($B.NativeLoad -and $R.OwnNatives.Count -gt 0) { Add-Reason $R 15 ('Loads its own native DLL: ' + (Join-Limited $R.OwnNatives 3)) }
    }

    # --- metadata / packaging ---------------------------------------------------
    $isLibrary = ($R.Manifest -match '(?im)^FMLModType\s*:\s*(?:LIBRARY|GAMELIBRARY)')
    if ($isMod -and -not $verified -and -not $R.OpenError -and -not $R.HasMeta -and -not $R.IsOptiFine -and -not $isLibrary) {
        Add-Reason $R 12 'No mod metadata (fabric.mod.json / mods.toml / mcmod.info) - not a normal mod'
    }
    if (-not $verified -and $R.Kind -ne 'Agent' -and $R.Manifest -match '(?im)^(?:Premain-Class|Agent-Class|Launcher-Agent-Class)\s*:') {
        Add-Reason $R 12 'Built as a Java agent (can hook into the game at launch)'
    }
    if (-not $verified -and $R.Manifest -match '(?im)^FMLCorePlugin\s*:') {
        Add-Reason $R 5 'Forge coremod (rewrites Minecraft code while loading)'
    }
    if (-not $verified -and -not $R.IsOptiFine -and $R.Manifest -match '(?im)^TweakClass\s*:') {
        Add-Reason $R 5 'Uses a launch tweaker (TweakClass) to modify the game'
    }

    if (-not $verified -and $R.Natives.Count -gt 0) {
        $exe = @($R.Natives | Where-Object { $_ -match '(?i)\.(?:exe|sys)\b' })
        if ($exe.Count -gt 0) { Add-Reason $R 12 ('Bundles Windows programs/drivers: ' + (Join-Limited $exe 3)) }
        elseif ($R.OwnNatives.Count -gt 0 -and -not $B.NativeLoad) { Add-Reason $R 4 ('Bundles unknown native code: ' + (Join-Limited $R.OwnNatives 3)) }
    }

    if ($isMod -and -not $verified) {
        foreach ($k in @($DisguiseMap.Keys)) {
            if ($R.Name -notmatch ('(?i)(?<![a-z])' + [regex]::Escape($k))) { continue }
            if ($k -eq 'optifine' -and $R.IsOptiFine) { break }
            $idText = (@($R.ModId, $R.ModName) | Where-Object { $_ }) -join ' '
            if ($R.HasMeta -and -not $idText) { break }   # multi-loader jar with its metadata in a nested jar
            if (-not $R.HasMeta -or $idText -notmatch ('(?i)' + $DisguiseMap[$k])) {
                $inside = 'something else'
                if ($R.ModId) { $inside = "mod '" + $R.ModId + "'" }
                Add-Reason $R 25 ("File is named like '" + $k + "' but contains " + $inside + ' - possible disguised cheat')
            }
            break
        }
    }

    $uText = (@($R.Name, $R.ModId, $R.ModName, $(if ($verified) { $R.Verified.Title } else { $null })) | Where-Object { $_ }) -join ' '
    $um = $UtilityRx.Match($uText)
    if ($um.Success) { Add-Reason $R 6 ("Gives an in-game advantage ('" + $um.Value + "') - allowed on some servers, banned on others") }

    if ($R.File.Attributes -band [IO.FileAttributes]::Hidden) { Add-Reason $R 10 'The file is hidden' }

    if ($GameStart -and $R.Kind -ne 'GameJar') {
        $changed = $R.File.LastWriteTime
        if ($R.File.CreationTime -gt $changed) { $changed = $R.File.CreationTime }
        if ($changed -gt $GameStart) {
            Add-Reason $R 15 ('Added or changed AFTER the game was started (' + $changed.ToString('HH:mm:ss') + ', game started ' + $GameStart.ToString('HH:mm:ss') + ')')
        }
    }

    foreach ($u in @($R.Source, $R.Referrer)) {
        if (-not $u) { continue }
        if ($CheatSiteRx.IsMatch($u)) { Add-Reason $R 50 ('Downloaded from a cheat-client website: ' + $u); break }
        if (-not $verified -and $FileHostRx.IsMatch($u)) { Add-Reason $R 5 ('Downloaded from a file-sharing site: ' + $u); break }
    }

    $R.Severity = 'CLEAN'
    if     ($R.IsMalware)    { $R.Severity = 'MALWARE' }
    elseif ($R.Score -ge 40) { $R.Severity = 'CHEAT' }
    elseif ($R.Score -ge 15) { $R.Severity = 'SUSPICIOUS' }
    elseif ($R.Score -ge 10) { $R.Severity = 'REVIEW' }
}

# =============================================================================
#  Injected clients: game memory, hidden DLLs, execution history
# =============================================================================

# Keywords searched for in the game's memory: the strong cheat-module names and
# the package names of known clients. A hit only counts when no jar on disk
# explains it (an injected client, or a cheat jar deleted after it loaded).
$MemKeywordInfo = @{}
foreach ($sig in $StringSigs) {
    if (-not $sig.Strong -or $sig.Name -eq 'HackedClient') { continue }   # "no hacked clients" is common chat/rules text
    $f = 0
    if ($sig.Before) { $f += 1 }
    if ($sig.After -eq 'L') { $f += 2 } elseif ($sig.After -eq 'Lc') { $f += 4 }
    foreach ($t in @($sig.L)) {
        foreach ($w in @(Expand-Template $t.ToLowerInvariant())) {
            if (-not $MemKeywordInfo.ContainsKey($w)) { $MemKeywordInfo[$w] = @{ Name = $sig.Name; Kind = 'Module'; Flags = $f } }
        }
    }
}
foreach ($k in @($CheatPackages.Keys)) {
    if (@($k.TrimEnd('/') -split '/').Count -lt 2) { continue }   # one-word packages (baritone/, vestige/ ...) are too generic for memory
    foreach ($w in @($k, $k.Replace('/', '.'))) { $MemKeywordInfo[$w] = @{ Name = $CheatPackages[$k]; Kind = 'Package'; Flags = 1 } }
}
$MemKeywords = [string[]]@($MemKeywordInfo.Keys)
$MemFlags    = [int[]]@($MemKeywords | ForEach-Object { $MemKeywordInfo[$_].Flags })
$MaxMemBytes = 12GB

# Windows-only helper: reads the game's memory (read-only) and searches it with
# the same keyword automaton, in 8-bit and UTF-16 text. Also lists DLL images
# hidden from the module list and manually mapped DLLs. Compiled on first use.
$WinHelperSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public sealed class ZoreMemScanV1 {
    [StructLayout(LayoutKind.Sequential)]
    private struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public ushort PartitionId;
        public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, [Out] byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern uint GetMappedFileNameW(IntPtr h, IntPtr addr, StringBuilder name, uint size);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern uint QueryDosDeviceW(string device, StringBuilder target, uint max);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid id, uint flags, IntPtr token, out IntPtr path);

    private static Dictionary<string, string> drives;

    // \Device\HarddiskVolume3\Users\x -> C:\Users\x
    public static string DevicePathToDos(string path) {
        if (path == null) return null;
        if (drives == null) {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            StringBuilder sb = new StringBuilder(1024);
            for (char c = 'A'; c <= 'Z'; c++) {
                sb.Length = 0;
                if (QueryDosDeviceW(c + ":", sb, 1024) > 0) { string dev = sb.ToString(); if (!d.ContainsKey(dev)) d[dev] = c + ":"; }
            }
            drives = d;
        }
        foreach (KeyValuePair<string, string> kv in drives) {
            if (path.StartsWith(kv.Key + "\\", StringComparison.OrdinalIgnoreCase)) return kv.Value + path.Substring(kv.Key.Length);
        }
        return path;
    }

    public static string KnownFolder(string guid) {
        try {
            IntPtr p;
            if (SHGetKnownFolderPath(new Guid(guid), 0, IntPtr.Zero, out p) != 0) return null;
            string s = Marshal.PtrToStringUni(p); Marshal.FreeCoTaskMem(p); return s;
        } catch { return null; }
    }

    // nxt holds the next state's row offset (state * alpha); term[row] = keywords end there
    private readonly int[] nxt; private readonly bool[] term; private readonly int[][] outs; private readonly int[] lens; private readonly int[] flags;
    private readonly int[] cmap = new int[256]; private readonly int alpha;
    public readonly int[] Counts; public readonly string[] Samples;
    public long BytesScanned; public long BytesTotal; public int Regions; public int ReadErrors;
    private long maxScan; private int nextRegion; private List<long[]> regionList; private IntPtr proc;
    public volatile bool Done; public string Error;
    public readonly List<string> HiddenImages = new List<string>();
    public readonly List<string> ManualMaps = new List<string>();

    // flags per keyword: 1 = no letter before, 2 = no letter after, 4 = no lower-case letter after
    public ZoreMemScanV1(string[] words, int[] wordFlags) {
        for (int i = 0; i < 256; i++) cmap[i] = -1;
        int a = 0;
        foreach (string w in words) foreach (char c in w) {
            if (c < 256 && cmap[c] < 0) {
                cmap[c] = a;
                char up = Char.ToUpperInvariant(c);
                if (up < 256 && up != c) cmap[up] = a;
                a++;
            }
        }
        alpha = a;
        List<int[]> go = new List<int[]>(); List<List<int>> o = new List<List<int>>();
        go.Add(Row()); o.Add(new List<int>());
        lens = new int[words.Length];
        for (int k = 0; k < words.Length; k++) {
            int s = 0; lens[k] = words[k].Length;
            foreach (char c in words[k]) {
                int ci = cmap[c];
                if (go[s][ci] < 0) { go[s][ci] = go.Count; go.Add(Row()); o.Add(new List<int>()); }
                s = go[s][ci];
            }
            o[s].Add(k);
        }
        int n = go.Count; int[] next = new int[n * alpha]; int[] fail = new int[n];
        Queue<int> q = new Queue<int>();
        for (int c = 0; c < alpha; c++) { int t = go[0][c]; if (t < 0) next[c] = 0; else { next[c] = t; q.Enqueue(t); } }
        while (q.Count > 0) {
            int s = q.Dequeue();
            o[s].AddRange(o[fail[s]]);
            for (int c = 0; c < alpha; c++) {
                int t = go[s][c];
                if (t < 0) next[s * alpha + c] = next[fail[s] * alpha + c];
                else { next[s * alpha + c] = t; fail[t] = next[fail[s] * alpha + c]; q.Enqueue(t); }
            }
        }
        nxt = new int[n * alpha]; term = new bool[n * alpha]; outs = new int[n * alpha][];
        for (int i = 0; i < n * alpha; i++) nxt[i] = next[i] * alpha;
        for (int st = 0; st < n; st++) { if (o[st].Count > 0) { term[st * alpha] = true; outs[st * alpha] = o[st].ToArray(); } }
        flags = wordFlags; Counts = new int[words.Length]; Samples = new string[words.Length];
    }
    private int[] Row() { int[] r = new int[alpha]; for (int i = 0; i < alpha; i++) r[i] = -1; return r; }

    private static bool IsLetter(int b) { return (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b >= 192; }
    private static bool IsLower(int b) { return (b >= 97 && b <= 122) || b >= 223; }

    private void Hit(int k, byte[] d, int len, int start, int end, bool wide) {
        int before, after;
        if (wide) { before = start >= 2 ? d[start - 2] : -1; after = end + 2 < len ? d[end + 2] : -1; }
        else { before = start >= 1 ? d[start - 1] : -1; after = end + 1 < len ? d[end + 1] : -1; }
        int f = flags[k];
        if ((f & 1) != 0 && before >= 0 && IsLetter(before)) return;
        if ((f & 2) != 0 && after >= 0 && IsLetter(after)) return;
        if ((f & 4) != 0 && after >= 0 && IsLower(after)) return;
        Interlocked.Increment(ref Counts[k]);
        if (Samples[k] == null) lock (Samples) if (Samples[k] == null) {
            int step = wide ? 2 : 1;
            int from = start - 40 * step; if (from < 0) from = start % step;
            int to = Math.Min(len - 1, end + 40 * step);
            StringBuilder sb = new StringBuilder();
            for (int i = from; i <= to; i += step) { int c = d[i]; sb.Append(c >= 32 && c < 127 ? (char)c : '.'); }
            Samples[k] = sb.ToString();
        }
    }

    // One pass: 8-bit text plus UTF-16LE text in both byte alignments.
    public void ScanBuffer(byte[] d, int len) {
        int s = 0, w0 = 0, w1 = 0;
        int[] map = cmap; int[] tbl = nxt; bool[] fin = term;
        for (int i = 0; i < len; i++) {
            int ci = map[d[i]];
            if (ci < 0) { s = 0; if ((i & 1) == 0) w0 = 0; else w1 = 0; continue; }
            s = tbl[s + ci];
            if (fin[s]) { int[] o = outs[s]; for (int j = 0; j < o.Length; j++) Hit(o[j], d, len, i - lens[o[j]] + 1, i, false); }
            if (i + 1 < len && d[i + 1] == 0) {
                if ((i & 1) == 0) {
                    w0 = tbl[w0 + ci];
                    if (fin[w0]) { int[] o = outs[w0]; for (int j = 0; j < o.Length; j++) Hit(o[j], d, len, i - 2 * (lens[o[j]] - 1), i, true); }
                } else {
                    w1 = tbl[w1 + ci];
                    if (fin[w1]) { int[] o = outs[w1]; for (int j = 0; j < o.Length; j++) Hit(o[j], d, len, i - 2 * (lens[o[j]] - 1), i, true); }
                }
            } else if ((i & 1) == 0) w0 = 0; else w1 = 0;
        }
    }

    public void Start(int pid, long[] moduleBases, long maxBytes) {
        Thread t = new Thread(delegate () {
            try { Run(pid, moduleBases, maxBytes); } catch (Exception e) { Error = e.Message; } finally { Done = true; }
        });
        t.IsBackground = true;
        t.Start();
    }

    private static bool Readable(uint p) { return p != 0 && (p & 0x01) == 0 && (p & 0x100) == 0; }
    private static bool Executable(uint p) { return (p & 0xF0) != 0; }

    private static bool HasPeHeader(IntPtr h, long b) {
        byte[] hdr = new byte[1024]; IntPtr got;
        if (!ReadProcessMemory(h, new IntPtr(b), hdr, new IntPtr(hdr.Length), out got) || got.ToInt64() < 1024) return false;
        if (hdr[0] != 0x4D || hdr[1] != 0x5A) return false;
        int lfanew = BitConverter.ToInt32(hdr, 0x3C);
        if (lfanew < 64 || lfanew > 1020) return false;
        return hdr[lfanew] == 0x50 && hdr[lfanew + 1] == 0x45 && hdr[lfanew + 2] == 0 && hdr[lfanew + 3] == 0;
    }

    private void Run(int pid, long[] moduleBases, long maxBytes) {
        IntPtr h = OpenProcess(0x0400 | 0x0010, false, pid);   // QUERY_INFORMATION | VM_READ - read only
        if (h == IntPtr.Zero) { Error = "access denied (error " + Marshal.GetLastWin32Error() + ")"; return; }
        try {
            HashSet<long> mods = new HashSet<long>(moduleBases ?? new long[0]);
            HashSet<long> seenImages = new HashSet<long>();
            IntPtr mbiSize = new IntPtr(Marshal.SizeOf(typeof(MBI)));
            List<long[]> regions = new List<long[]>();
            long addr = 0; MBI m;
            while (VirtualQueryEx(h, new IntPtr(addr), out m, mbiSize) != IntPtr.Zero) {
                long b = m.BaseAddress.ToInt64(); long size = m.RegionSize.ToInt64();
                if (m.State == 0x1000 && Readable(m.Protect)) {                       // MEM_COMMIT
                    if (m.Type == 0x1000000) {                                         // MEM_IMAGE
                        long ab = m.AllocationBase.ToInt64();
                        if (!mods.Contains(ab) && seenImages.Add(ab)) {
                            StringBuilder sb = new StringBuilder(1024);
                            HiddenImages.Add(GetMappedFileNameW(h, m.AllocationBase, sb, 1024) > 0 ? DevicePathToDos(sb.ToString()) : ("0x" + ab.ToString("X")));
                        }
                    } else if (m.Type == 0x20000 && Executable(m.Protect) && size >= 4096) {  // MEM_PRIVATE + executable
                        if (HasPeHeader(h, b)) ManualMaps.Add("0x" + b.ToString("X") + " (" + (size / 1024) + " KB)");
                    }
                    regions.Add(new long[] { b, size });
                    BytesTotal += size;
                }
                long nx = b + size;
                if (nx <= addr) break;
                addr = nx;
            }
            Regions = regions.Count;
            if (BytesTotal > maxBytes) BytesTotal = maxBytes;
            regionList = regions; maxScan = maxBytes; proc = h; nextRegion = 0;
            int workers = Math.Max(1, Math.Min(4, Environment.ProcessorCount));
            Thread[] pool = new Thread[workers];
            for (int w = 0; w < workers; w++) { pool[w] = new Thread(Worker); pool[w].IsBackground = true; pool[w].Start(); }
            for (int w = 0; w < workers; w++) pool[w].Join();
        } finally { CloseHandle(h); }
    }

    private void Worker() {
        const int Chunk = 16 * 1024 * 1024; const int Overlap = 256;
        byte[] buf = new byte[Chunk + Overlap];
        while (true) {
            int idx = Interlocked.Increment(ref nextRegion) - 1;
            if (idx >= regionList.Count) return;
            long[] r = regionList[idx];
            long off = 0;
            while (off < r[1]) {
                if (Interlocked.Read(ref BytesScanned) >= maxScan) return;
                int want = (int)Math.Min((long)Chunk + Overlap, r[1] - off);
                IntPtr got;
                if (ReadProcessMemory(proc, new IntPtr(r[0] + off), buf, new IntPtr(want), out got) && got.ToInt64() > 0) ScanBuffer(buf, (int)got.ToInt64());
                else Interlocked.Increment(ref ReadErrors);
                long adv = Math.Min((long)Chunk, r[1] - off);
                off += adv; Interlocked.Add(ref BytesScanned, adv);
            }
        }
    }
}
'@

$WinHelper = @{ Ready = $false; Tried = $false; Error = $null }
function Initialize-WinHelper {
    if ($WinHelper.Tried) { return $WinHelper.Ready }
    $WinHelper.Tried = $true
    try {
        if (-not ('ZoreMemScanV1' -as [type])) { Add-Type -TypeDefinition $WinHelperSource -Language CSharp -ErrorAction Stop }
        $WinHelper.Ready = $true
    } catch {
        $WinHelper.Error = $_.Exception.Message
    }
    return $WinHelper.Ready
}

function Invoke-MemoryScan($Inst, $Results) {
    $area = 'Minecraft PID ' + $Inst.Pid
    if (-not [Environment]::Is64BitProcess) {
        Add-Finding 'INFO' $area 'Game memory was not scanned' 'Use 64-bit PowerShell (not "Windows PowerShell (x86)") for the memory scan.'
        return
    }
    if (-not (Initialize-WinHelper)) {
        Add-Finding 'INFO' $area 'Game memory was not scanned' ('The memory scanner could not be loaded (' + $WinHelper.Error + '). Antivirus or a locked-down PowerShell can block it.')
        return
    }
    $scanner = New-Object ZoreMemScanV1 -ArgumentList $MemKeywords, $MemFlags
    $bases = [long[]]@($Inst.ModuleBases | Where-Object { $_ })
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $scanner.Start([int]$Inst.Pid, $bases, [long]$MaxMemBytes)
    while (-not $scanner.Done) {
        Start-Sleep -Milliseconds 250
        if (-not $Z.NoProgress) {
            $w = (Get-ConsoleWidth) - 1
            $t = ('        reading game memory: {0:N0} / {1:N0} MB' -f ($scanner.BytesScanned / 1MB), ($scanner.BytesTotal / 1MB))
            Write-Host ("`r" + $t.PadRight($w).Substring(0, $w)) -NoNewline -ForegroundColor DarkGray
        }
    }
    Clear-Progress
    if ($scanner.Error) {
        Add-Finding 'INFO' $area ('Could not read the game memory: ' + $scanner.Error) 'Run PowerShell as Administrator (the game is probably running elevated).'
        return
    }
    Out-Done ('PID ' + $Inst.Pid + ': ' + [Math]::Round($scanner.BytesScanned / 1MB) + ' MB of game memory scanned in ' + [Math]::Round($sw.Elapsed.TotalSeconds, 1) + ' s')
    $Z.MemNotes.Add('PID ' + $Inst.Pid + ': ' + [Math]::Round($scanner.BytesScanned / 1MB) + ' MB scanned')
    Publish-MemoryResult $Inst $Results $scanner
}

# Turns raw memory hits into findings ($Scan: Counts, Samples, HiddenImages, ManualMaps).
function Publish-MemoryResult($Inst, $Results, $Scan) {
    $area = 'Minecraft PID ' + $Inst.Pid

    # Everything the jars on disk can explain (mods, agents, game jars).
    $explained = @{}; $explainedClients = @{}
    foreach ($r in $Results) {
        foreach ($k in @($r.Strong.Keys) + @($r.Weak.Keys) + @($r.TextNames.Keys)) { $explained[$k] = $true }
        foreach ($k in @($r.Known.Keys) + @($r.ApiRefs.Keys)) { $explainedClients[$k] = $true }
    }

    $modules = [ordered]@{}; $clients = [ordered]@{}
    for ($i = 0; $i -lt $MemKeywords.Length; $i++) {
        if ($Scan.Counts[$i] -le 0) { continue }
        $info = $MemKeywordInfo[$MemKeywords[$i]]
        $sample = $Scan.Samples[$i]
        if ($info.Kind -eq 'Package') {
            if (-not $explainedClients.ContainsKey($info.Name) -and -not $clients.Contains($info.Name)) { $clients[$info.Name] = $sample }
        } elseif (-not $explained.ContainsKey($info.Name) -and -not $modules.Contains($info.Name)) {
            $modules[$info.Name] = $sample
        }
    }

    foreach ($c in @($clients.Keys)) {
        Add-Finding 'CHEAT' $area ('Code of the cheat client ' + $c + ' is loaded in the game, but no jar on disk contains it (injected or deleted after launch)') ('memory: "' + $clients[$c] + '"')
    }
    $n = $modules.Count
    if ($n -gt 0) {
        $names = Join-Limited @($modules.Keys) 12
        $examples = (@(@($modules.Keys) | Select-Object -First 3) | ForEach-Object { $_ + ': "' + $modules[$_] + '"' }) -join '   |   '
        if ($n -ge 4) {
            Add-Finding 'CHEAT' $area ('Cheat modules found in game memory that no jar on disk contains (' + $n + '): ' + $names) ('Injected client or a cheat jar deleted after launch. ' + $examples)
        } elseif ($n -ge 2) {
            Add-Finding 'SUSPICIOUS' $area ('Cheat module names found in game memory (' + $n + '): ' + $names) ('Could be an injected client, or chat / server text. ' + $examples)
        } else {
            Add-Finding 'REVIEW' $area ('A cheat module name was found in game memory: ' + $names) ('Often just chat or server text. ' + $examples)
        }
    }

    foreach ($p in $Scan.HiddenImages) {
        if ($p -match '(?i)\.(?:mui|mun)$' -or ($env:windir -and $p.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase))) { continue }
        $sev = 'REVIEW'
        if ($UserDropDirRx.IsMatch($p) -or $p -match '(?i)\\AppData\\' -or $p -match '^0x') { $sev = 'SUSPICIOUS' }
        Add-Finding $sev $area ('DLL hidden from the game''s module list: ' + [IO.Path]::GetFileName($p)) ($p + '   (unlinked DLLs are a classic injection trick)')
    }
    foreach ($mm in $Scan.ManualMaps) {
        Add-Finding 'SUSPICIOUS' $area 'Manually mapped DLL hidden in game memory' ('At ' + $mm + ' - a program image loaded without Windows'' loader, which is how injectors hide cheat DLLs')
    }
}

function ConvertFrom-Rot13([string]$Text) {
    $sb = New-Object System.Text.StringBuilder $Text.Length
    foreach ($c in $Text.ToCharArray()) {
        $n = [int]$c
        if ($n -ge 65 -and $n -le 90) { $n = (($n - 65 + 13) % 26) + 65 }
        elseif ($n -ge 97 -and $n -le 122) { $n = (($n - 97 + 13) % 26) + 97 }
        [void]$sb.Append([char]$n)
    }
    return $sb.ToString()
}

function Get-ExecutionHistory {
    $entries = New-Object System.Collections.Generic.List[object]
    $notes   = New-Object System.Collections.Generic.List[string]
    $helper  = Initialize-WinHelper

    # UserAssist: programs started from Explorer (no admin needed). Value names are ROT13.
    try {
        foreach ($k in @(Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' -ErrorAction Stop)) {
            $key = Get-Item -LiteralPath (Join-Path $k.PSPath 'Count') -ErrorAction SilentlyContinue
            if (-not $key) { continue }
            foreach ($vn in $key.GetValueNames()) {
                $path = ConvertFrom-Rot13 $vn
                if ($path -notmatch '(?i)\.exe$') { continue }
                $data = $key.GetValue($vn)
                if (-not ($data -is [byte[]]) -or $data.Length -lt 68) { continue }
                $ft = [BitConverter]::ToInt64($data, 60)
                if ($ft -le 0) { continue }
                $gm = [regex]::Match($path, '^\{([0-9A-Fa-f-]{36})\}(.*)$')
                if ($gm.Success -and $helper) {
                    $folder = [ZoreMemScanV1]::KnownFolder($gm.Groups[1].Value)
                    if ($folder) { $path = $folder + $gm.Groups[2].Value }
                }
                $entries.Add([pscustomobject]@{ Path = $path; Time = [DateTime]::FromFileTimeUtc($ft).ToLocalTime(); Source = 'UserAssist' })
            }
        }
    } catch { }

    # BAM: every program Windows ran, about the last week (needs admin).
    $bamOk = $false
    foreach ($root in @('HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings')) {
        try {
            foreach ($sidKey in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                $bamOk = $true
                foreach ($vn in $sidKey.GetValueNames()) {
                    if ($vn -notmatch '^\\Device\\') { continue }
                    $data = $sidKey.GetValue($vn)
                    if (-not ($data -is [byte[]]) -or $data.Length -lt 8) { continue }
                    $ft = [BitConverter]::ToInt64($data, 0)
                    if ($ft -le 0) { continue }
                    $path = $vn
                    if ($helper) { $path = [ZoreMemScanV1]::DevicePathToDos($vn) }
                    $entries.Add([pscustomobject]@{ Path = $path; Time = [DateTime]::FromFileTimeUtc($ft).ToLocalTime(); Source = 'BAM' })
                }
            }
        } catch { }
    }
    if (-not $bamOk) { $notes.Add('BAM') }

    # Prefetch: one file per program run recently (needs admin).
    try {
        $pf = Join-Path $env:windir 'Prefetch'
        foreach ($f in @(Get-ChildItem -LiteralPath $pf -Filter '*.pf' -Force -ErrorAction Stop)) {
            $m = [regex]::Match($f.Name, '^(.+)-[0-9A-Fa-f]{8}\.pf$')
            if ($m.Success) { $entries.Add([pscustomobject]@{ Path = $m.Groups[1].Value; Time = $f.LastWriteTime; Source = 'Prefetch' }) }
        }
    } catch { $notes.Add('Prefetch') }

    return @{ Entries = $entries; Notes = $notes }
}

function Test-ExecutionHistory($Instances) {
    if (-not $IsWin) { return 0 }
    $hist = Get-ExecutionHistory
    $count = Measure-ExecutionHistory $hist.Entries $Instances
    if ($hist.Notes.Count -gt 0) {
        Add-Finding 'INFO' 'Execution history' ('Not checked without Administrator: ' + ($hist.Notes -join ', ')) 'Run PowerShell as Administrator to also see programs that ran and deleted themselves.'
    }
    return $count
}

function Measure-ExecutionHistory($Entries, $Instances) {
    $gameStart = $null
    foreach ($i in $Instances) { if ($i.Start -and (-not $gameStart -or $i.Start -lt $gameStart)) { $gameStart = $i.Start } }

    # merge the sources per program
    $byPath = @{}
    foreach ($e in $Entries) {
        $k = ([string]$e.Path).ToLowerInvariant()
        if (-not $byPath.ContainsKey($k)) { $byPath[$k] = @{ Path = [string]$e.Path; Time = $e.Time; Sources = New-Object System.Collections.Generic.List[string] } }
        $x = $byPath[$k]
        if ($e.Time -gt $x.Time) { $x.Time = $e.Time }
        if (-not $x.Sources.Contains($e.Source)) { $x.Sources.Add($e.Source) }
    }

    $count = 0
    $now = Get-Date
    foreach ($x in @($byPath.Values | Sort-Object -Property @{ Expression = { $_.Time }; Descending = $true })) {
        $leaf = [IO.Path]::GetFileName($x.Path)
        $base = [IO.Path]::GetFileNameWithoutExtension($leaf)
        $sev = $null; $title = $null
        if     ($CheatLoaderRx.IsMatch($base)) { $sev = 'CHEAT'; $title = 'Ghost-client loader was run: ' + $leaf }
        elseif ($CheatNameRx.IsMatch($leaf) -or $LooseCheatNameRx.IsMatch($base)) { $sev = 'SUSPICIOUS'; $title = 'Cheat program was run: ' + $leaf }
        elseif ($ClickerRx.IsMatch($base))  { $sev = 'SUSPICIOUS'; $title = 'Auto-clicker / macro program was run: ' + $leaf }
        elseif ($InjectorRx.IsMatch($base)) { $sev = 'SUSPICIOUS'; $title = 'DLL injector / memory editor was run: ' + $leaf }
        elseif ($ReviewProcRx.IsMatch($base)) { $sev = 'REVIEW'; $title = 'Tool used to hide cheats or edit jars was run: ' + $leaf }
        elseif ($gameStart -and $x.Time -gt $gameStart -and $x.Path -match '^[A-Za-z]:\\' -and $UserDropDirRx.IsMatch($x.Path)) {
            # Injectors have to run while the game is open, then often delete themselves.
            if (-not (Test-Path -LiteralPath $x.Path)) {
                $sev = 'SUSPICIOUS'; $title = 'A program ran while the game was open and has since been deleted: ' + $leaf
            } else {
                $st = 'Unknown'
                try { $st = [string](Get-AuthenticodeSignature -LiteralPath $x.Path -ErrorAction Stop).Status } catch { }
                if ($st -ne 'Valid') { $sev = 'REVIEW'; $title = 'Unsigned program ran from a download/temp folder while the game was open: ' + $leaf }
            }
        }
        if (-not $sev) { continue }
        if (($now - $x.Time).TotalDays -gt 14) {
            if ($sev -eq 'CHEAT') { $sev = 'SUSPICIOUS' } elseif ($sev -eq 'SUSPICIOUS') { $sev = 'REVIEW' }
            $title += '  (over 2 weeks ago)'
        }
        Add-Finding $sev 'Execution history' $title ($x.Path + '   last run ' + $x.Time.ToString('yyyy-MM-dd HH:mm') + '   (' + ($x.Sources -join ', ') + ')')
        $count++
    }
    return $count
}

# =============================================================================
#  Traces left on the PC
# =============================================================================
function Find-Traces($Roots) {
    $reported = @{}
    foreach ($root in $Roots) {
        # anything in the game folder or its config folder named like a cheat client
        foreach ($dir in @($root, (Join-Path $root 'config'))) {
            if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
            foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
                if ($ClientFolderRx.IsMatch($item.Name) -and -not $reported.ContainsKey($item.FullName)) {
                    $reported[$item.FullName] = $true
                    Add-Finding 'SUSPICIOUS' 'Traces' ('Cheat client folder/file found: ' + $item.Name) ($item.FullName + '   (last changed ' + $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + ')')
                }
            }
        }
        foreach ($rel in @($TraceFolders.Keys)) {
            $p = Join-Path $root $rel
            if ((Test-Path -LiteralPath $p -PathType Container) -and -not $reported.ContainsKey((Get-Item -LiteralPath $p -Force).FullName)) {
                $reported[(Get-Item -LiteralPath $p -Force).FullName] = $true
                $when = ''
                try { $when = (Get-Item -LiteralPath $p -Force).LastWriteTime.ToString('yyyy-MM-dd HH:mm') } catch { }
                Add-Finding 'SUSPICIOUS' 'Traces' ($TraceFolders[$rel] + ' data folder found') ($p + '   (last changed ' + $when + ')')
            }
        }
        $vdir = Join-Path $root 'versions'
        if (Test-Path -LiteralPath $vdir -PathType Container) {
            foreach ($d in @(Get-ChildItem -LiteralPath $vdir -Directory -Force -ErrorAction SilentlyContinue)) {
                if ($CheatNameRx.IsMatch($d.Name)) {
                    Add-Finding 'SUSPICIOUS' 'Traces' ('Cheat client installed as a game version: ' + $d.Name) $d.FullName
                }
            }
        }
    }
    # AppData / LocalAppData / home / Documents: only exact client names (Prestige, Vape, Drip, ...)
    foreach ($dir in @($AppData, $env:LOCALAPPDATA, $UserDir, (Join-Path $UserDir 'Documents')) | Where-Object { $_ } | Select-Object -Unique) {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
            if ($ClientFolderStrictRx.IsMatch($item.Name) -and -not $reported.ContainsKey($item.FullName)) {
                $reported[$item.FullName] = $true
                Add-Finding 'SUSPICIOUS' 'Traces' ('Cheat client folder/file found: ' + $item.Name) ($item.FullName + '   (last changed ' + $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + ')')
            }
        }
    }
    foreach ($rel in @($HomeTraceFolders.Keys)) {
        $p = Join-Path $UserDir $rel
        if (Test-Path -LiteralPath $p -PathType Container) {
            $sev = 'SUSPICIOUS'
            if ($rel -eq '.weave') { $sev = 'REVIEW' }
            Add-Finding $sev 'Traces' ($HomeTraceFolders[$rel] + ' folder found') $p
        }
    }
}

function Find-OtherInstanceCheats([string]$ScannedDir) {
    $sep = [IO.Path]::DirectorySeparatorChar
    $globs = @(
        (Join-Path $AppData '.minecraft\mods'),
        (Join-Path $AppData 'PrismLauncher\instances\*\.minecraft\mods'),
        (Join-Path $AppData 'PrismLauncher\instances\*\minecraft\mods'),
        (Join-Path $AppData 'ModrinthApp\profiles\*\mods'),
        (Join-Path $AppData 'com.modrinth.theseus\profiles\*\mods'),
        (Join-Path $AppData 'gdlauncher_next\instances\*\mods'),
        (Join-Path $AppData 'ATLauncher\instances\*\mods'),
        (Join-Path $UserDir 'curseforge\minecraft\Instances\*\mods')
    )
    $seen = @{}
    foreach ($g in $globs) {
        $g = $g.Replace('\', $sep)
        foreach ($d in @(Get-Item -Path $g -Force -ErrorAction SilentlyContinue)) {
            if (-not $d.PSIsContainer) { continue }
            if ($seen.ContainsKey($d.FullName) -or (Test-SamePath $d.FullName $ScannedDir)) { continue }
            $seen[$d.FullName] = $true
            foreach ($f in @(Get-ChildItem -LiteralPath $d.FullName -File -Force -ErrorAction SilentlyContinue)) {
                if ($JarLikeRx.IsMatch($f.Name) -and $CheatNameRx.IsMatch($f.Name)) {
                    Add-Finding 'SUSPICIOUS' 'Other instances' ('Cheat jar in another Minecraft instance: ' + $f.Name) $f.FullName
                }
            }
        }
    }
}

function Find-RecycledFiles {
    if (-not $IsWin) { return }
    try {
        $shell = New-Object -ComObject Shell.Application
        $bin = $shell.NameSpace(10)
        if (-not $bin) { return }
        $cutoff = (Get-Date).AddDays(-7)
        foreach ($item in $bin.Items()) {
            $path = [string]$item.Path
            $name = [string]$item.Name
            if ($path -notmatch '(?i)\.(?:jar|exe|dll|zip)$' -and $name -notmatch '(?i)\.(?:jar|exe|dll|zip)$') { continue }
            $deleted = $null; $from = ''
            try { $deleted = $item.ExtendedProperty('System.Recycle.DateDeleted') } catch { }
            try { $from = [string]$item.ExtendedProperty('System.Recycle.DeletedFrom') } catch { }
            $when = ''
            if ($deleted -is [datetime]) { $when = $deleted.ToString('yyyy-MM-dd HH:mm') }
            $detail = ('Deleted ' + $when + ' from ' + $from).Trim()
            if ($CheatNameRx.IsMatch($name) -or $ClickerRx.IsMatch($name)) {
                Add-Finding 'SUSPICIOUS' 'Recycle Bin' ('Deleted cheat file: ' + $name) $detail
            } elseif ($path -match '(?i)\.jar$' -and ($deleted -is [datetime]) -and $deleted -gt $cutoff -and
                      $from -match '(?i)minecraft|mods|instances|lunar|feather|curseforge|modrinth|prism') {
                Add-Finding 'REVIEW' 'Recycle Bin' ('Mod jar deleted in the last 7 days: ' + $name) $detail
            }
        }
    } catch { }
}

function Find-DownloadedCheats {
    $dirs = @()
    try { $dirs += [Environment]::GetFolderPath('Desktop') } catch { }
    $dirs += (Join-Path $UserDir 'Downloads')
    foreach ($d in @($dirs | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $d -PathType Container)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d -File -Recurse -Depth 1 -Force -ErrorAction SilentlyContinue)) {
            if ($f.Name -notmatch '(?i)\.(?:jar|exe|dll|zip|rar|7z|msi)$') { continue }
            if ($CheatNameRx.IsMatch($f.Name)) {
                Add-Finding 'SUSPICIOUS' 'Downloads' ('Cheat download found: ' + $f.Name) ($f.FullName + '   (' + $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + ')')
            } elseif ($ClickerRx.IsMatch($f.BaseName) -or $InjectorRx.IsMatch($f.BaseName)) {
                Add-Finding 'REVIEW' 'Downloads' ('Auto-clicker / injector download found: ' + $f.Name) ($f.FullName + '   (' + $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + ')')
            }
        }
    }
}

function Find-SuspiciousPrograms($Instances) {
    $gamePids = @{}
    foreach ($i in $Instances) { $gamePids[[string]$i.Pid] = $true }
    $seen = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        if ($gamePids.ContainsKey([string]$p.Id)) { continue }
        $n = [string]$p.ProcessName
        if ($seen.ContainsKey($n)) { continue }
        $title = ''
        try { $title = [string]$p.MainWindowTitle } catch { }
        $label = $n
        if ($title) { $label = $n + '  -  "' + $title + '"' }
        $path = ''
        try { $path = [string]$p.Path } catch { }
        if ($path) { $label = $label + '   ' + $path }

        if ($CheatLoaderRx.IsMatch($n)) {
            Add-Finding 'CHEAT' 'Running programs' ('Ghost-client loader is running: ' + $n) $label
        } elseif ($title -and $CheatNameRx.IsMatch($title)) {
            Add-Finding 'SUSPICIOUS' 'Running programs' 'An open window mentions a cheat client' $label
        } elseif ($ClickerRx.IsMatch($n) -or ($title -and $ClickerRx.IsMatch($title))) {
            Add-Finding 'SUSPICIOUS' 'Running programs' ('Auto-clicker / macro program is running: ' + $n) $label
        } elseif ($InjectorRx.IsMatch($n)) {
            Add-Finding 'SUSPICIOUS' 'Running programs' ('DLL injector / memory editor is running: ' + $n) $label
        } elseif ($ReviewProcRx.IsMatch($n) -or ($title -and $ReviewTitleRx.IsMatch($title))) {
            Add-Finding 'REVIEW' 'Running programs' ('Tool often used to hide cheats or edit jars is running: ' + $n) $label
        } else {
            continue
        }
        $seen[$n] = $true
    }
}

# =============================================================================
#  Results
# =============================================================================
function Get-ModInfoLine($R) {
    $parts = @()
    if ($R.Verified) { $parts += ('Modrinth: ' + $R.Verified.Title + ' ' + $R.Verified.Version) }
    if ($R.ModName -or $R.ModId) {
        $t = (@($R.ModName, $R.ModVersion) | Where-Object { $_ }) -join ' '
        if ($R.ModId) { $t = ($t + ' (id: ' + $R.ModId + ')').Trim() }
        $parts += $t
    }
    if ($R.Loader)  { $parts += $R.Loader }
    if ($R.Classes) { $parts += ($R.Classes.ToString() + ' classes') }
    return ($parts -join '  |  ')
}

function Show-ModResults($Results) {
    Out-Section 'MODS'
    if ($Results.Count -eq 0) {
        Out-Tag 'INFO'; Out-Row 'No jar files found in that folder.'
        return
    }

    $flagged = @($Results | Where-Object { $SevRank[$_.Severity] -ge 1 } | Sort-Object -Property @{ Expression = { $_.Score }; Descending = $true })
    foreach ($r in $flagged) {
        Out-Tag $r.Severity
        Out-Part $r.Name 'White'
        if ($r.Kind -ne 'Mod') { Out-Part ('   (' + $KindLabel[$r.Kind] + ')') 'DarkGray' }
        Out-Row ''
        $info = Get-ModInfoLine $r
        if ($info) { Out-Detail $info 'Gray' }
        foreach ($why in $r.Reasons) { Out-Detail ('- ' + $why) $SevColor[$r.Severity] }
        foreach ($ev in $r.Evidence) { Out-Detail ('    found: ' + $ev) 'DarkGray' }
        if ($r.Source) { Out-Detail ('Downloaded from: ' + $r.Source) 'DarkGray' }
        Out-Detail ('Path: ' + $r.Path + '   SHA-1: ' + $r.Sha1) 'DarkGray'
        Out-Row ''
    }

    $unknown = @($Results | Where-Object { $_.Severity -eq 'CLEAN' -and -not $_.Verified } | Sort-Object -Property @{ Expression = { $_.Name } })
    if ($unknown.Count -gt 0) {
        Out-Row ('  Not on Modrinth, no cheat code found (' + $unknown.Count + ') - check these by hand if you do not recognise them:') 'Gray'
        foreach ($r in $unknown) {
            Out-Tag 'UNKNOWN'
            Out-Part $r.Name 'Gray'
            $extra = (@($r.ModName, $r.ModVersion) | Where-Object { $_ }) -join ' '
            if ($r.Kind -ne 'Mod') { $extra = ($extra + ' (' + $KindLabel[$r.Kind] + ')').Trim() }
            if ($extra) { Out-Part ('   ' + $extra) 'DarkGray' }
            Out-Row ''
            if ($r.Source) { Out-Detail ('Downloaded from: ' + $r.Source) }
        }
        Out-Row ''
    }

    $verified = @($Results | Where-Object { $_.Severity -eq 'CLEAN' -and $_.Verified } | Sort-Object -Property @{ Expression = { $_.Verified.Title } })
    if ($verified.Count -gt 0) {
        Out-Row ('  Verified legit on Modrinth (' + $verified.Count + '):') 'Gray'
        foreach ($r in $verified) {
            Out-Tag 'VERIFIED'
            Out-Part ($r.Verified.Title + ' ' + $r.Verified.Version) 'Green'
            Out-Row ('   ' + $r.Name) 'DarkGray'
        }
    }
}

function Show-Findings {
    Out-Section 'GAME PROCESS & SYSTEM'
    $important = @($Z.Findings | Where-Object { $SevRank[$_.Severity] -ge 1 })
    if ($important.Count -eq 0) {
        Out-Tag 'CLEAN'; Out-Row 'Nothing suspicious found outside the mods folder.' 'Green'
    }
    foreach ($sev in @('MALWARE', 'CHEAT', 'SUSPICIOUS', 'REVIEW', 'INFO')) {
        foreach ($f in $Z.Findings) {
            if ($f.Severity -ne $sev) { continue }
            Out-Tag $sev
            $titleColor = 'White'
            if ($sev -eq 'INFO') { $titleColor = 'Gray' }
            Out-Part $f.Title $titleColor
            Out-Row ('   [' + $f.Area + ']') 'DarkGray'
            if ($f.Detail) { Out-Detail $f.Detail }
        }
    }
}

function Show-Summary($Results, $Instances, [string]$Target, [bool]$ModrinthOnline, [TimeSpan]$Elapsed) {
    $count = @{ MALWARE = 0; CHEAT = 0; SUSPICIOUS = 0; REVIEW = 0 }
    foreach ($r in $Results)    { if ($count.ContainsKey($r.Severity)) { $count[$r.Severity]++ } }
    $fCount = @{ CHEAT = 0; SUSPICIOUS = 0; REVIEW = 0 }
    foreach ($f in $Z.Findings) { if ($fCount.ContainsKey($f.Severity)) { $fCount[$f.Severity]++ } }
    $verified = @($Results | Where-Object { $_.Verified }).Count
    $deep     = @($Results | Where-Object { $_.Deep }).Count

    Out-Section 'SUMMARY'
    Out-Row ('  Scanned folder      : ' + $Target)
    Out-Row ('  Running game        : ' + $(if ($Instances.Count -gt 0) { ($Instances | ForEach-Object { 'PID ' + $_.Pid + ' (' + $_.Loader + ' ' + $_.VersionId + ')' }) -join ', ' } else { 'not running - live checks skipped' }))
    Out-Row ('  Jars scanned        : ' + $Results.Count + '   (' + $verified + ' verified on Modrinth, ' + $deep + ' deep-scanned)')
    if (-not $ModrinthOnline) { Out-Row '  Modrinth            : unreachable - every jar was deep-scanned instead' 'Yellow' }
    if ($Z.MemNotes.Count -gt 0) { Out-Row ('  Game memory         : ' + ($Z.MemNotes -join ', ')) }
    Out-Part '  Flagged jars        : '
    if ($count.MALWARE) { Out-Part ([string]$count.MALWARE + ' MALWARE, ') 'Red' }
    Out-Part ([string]$count.CHEAT + ' cheat') $(if ($count.CHEAT) { 'Red' } else { 'Gray' })
    Out-Part ', '
    Out-Part ([string]$count.SUSPICIOUS + ' suspicious') $(if ($count.SUSPICIOUS) { 'Yellow' } else { 'Gray' })
    Out-Part ', '
    Out-Row ([string]$count.REVIEW + ' to review') $(if ($count.REVIEW) { 'Magenta' } else { 'Gray' })
    Out-Part '  Other findings      : '
    Out-Part ([string]$fCount.CHEAT + ' cheat') $(if ($fCount.CHEAT) { 'Red' } else { 'Gray' })
    Out-Part ', '
    Out-Part ([string]$fCount.SUSPICIOUS + ' suspicious') $(if ($fCount.SUSPICIOUS) { 'Yellow' } else { 'Gray' })
    Out-Part ', '
    Out-Row ([string]$fCount.REVIEW + ' to review') $(if ($fCount.REVIEW) { 'Magenta' } else { 'Gray' })
    Out-Row ('  Scan time           : ' + [Math]::Round($Elapsed.TotalSeconds, 1) + ' s')
    Out-Row ''

    $verdict = 'CLEAN - NO CHEATS FOUND'; $color = 'Green'
    if (($count.REVIEW + $fCount.REVIEW) -gt 0)         { $verdict = 'NO CHEATS FOUND - SOME THINGS TO REVIEW'; $color = 'Magenta' }
    if (($count.SUSPICIOUS + $fCount.SUSPICIOUS) -gt 0) { $verdict = 'SUSPICIOUS - CHECK THE FLAGGED ITEMS';  $color = 'Yellow' }
    if (($count.CHEAT + $fCount.CHEAT) -gt 0)           { $verdict = 'CHEATS DETECTED';                       $color = 'Red' }
    if ($count.MALWARE -gt 0)                           { $verdict = 'MALWARE DETECTED - DO NOT RUN THIS JAR';  $color = 'Red' }
    $inner = 62
    Out-Row ('  ' + $Ch.DTL + ($Ch.DH * $inner) + $Ch.DTR) $color
    Out-Row ('  ' + $Ch.DV + ('   VERDICT:  ' + $verdict).PadRight($inner) + $Ch.DV) $color
    Out-Row ('  ' + $Ch.DBL + ($Ch.DH * $inner) + $Ch.DBR) $color
    Out-Row ''
    Out-Row '  No scanner can promise a player is clean: private / heavily obfuscated clients, external' 'DarkGray'
    Out-Row '  (DLL) ghost clients and memory-only injectors can hide from file checks. Use this together' 'DarkGray'
    Out-Row '  with a normal screenshare.' 'DarkGray'
}

function Save-Report {
    $dir = $null
    try { $dir = [Environment]::GetFolderPath('Desktop') } catch { }
    if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { $dir = $UserDir }
    $file = Join-Path $dir ('ZoreInspector_' + (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss') + '.txt')
    $all = New-Object System.Collections.Generic.List[string]
    $all.Add('Zore Client Inspector v' + $ZoreVersion)
    $all.Add('Date     : ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    $all.Add('Computer : ' + $env:COMPUTERNAME + '   User: ' + $env:USERNAME)
    $all.AddRange($Z.Report)
    try {
        [IO.File]::WriteAllLines($file, $all.ToArray(), (New-Object System.Text.UTF8Encoding($true)))
        return $file
    } catch { return $null }
}

# =============================================================================
#  Main
# =============================================================================
function Read-TargetPath([string]$Default) {
    while ($true) {
        Write-Host ''
        Write-Host 'Enter path to the mods folder: ' -ForegroundColor White -NoNewline
        Write-Host '(press Enter to use default)' -ForegroundColor DarkGray
        Write-Host ('Default: ' + $Default) -ForegroundColor DarkGray
        Write-Host 'PATH: ' -ForegroundColor White -NoNewline
        $answer = $null
        if ($env:ZORE_PATH) { $answer = $env:ZORE_PATH; Write-Host $answer } else { $answer = Read-Host }
        $answer = ([string]$answer).Trim().Trim('"').Trim("'")
        if ($answer -match '^(?i)(?:q|quit|exit)$') { return $null }
        if (-not $answer) { $answer = $Default }
        $answer = [Environment]::ExpandEnvironmentVariables($answer)
        if (Test-Path -LiteralPath $answer) {
            $item = Get-Item -LiteralPath $answer -Force
            if ($item.PSIsContainer) {
                # A game/instance folder was given instead of its mods folder.
                $hasJars = @(Get-ChildItem -LiteralPath $item.FullName -Filter '*.jar' -File -Force -ErrorAction SilentlyContinue).Count -gt 0
                $sub = Join-Path $item.FullName 'mods'
                if (-not $hasJars -and (Test-Path -LiteralPath $sub -PathType Container)) { return (Get-Item -LiteralPath $sub -Force).FullName }
            }
            return $item.FullName
        }
        Write-Host '  That path does not exist. Try again, or type q to quit.' -ForegroundColor Red
        if ($env:ZORE_PATH) { return $null }
    }
}

function Get-ModFiles([string]$Target) {
    if (Test-Path -LiteralPath $Target -PathType Leaf) { return @(Get-Item -LiteralPath $Target -Force) }
    return @(Get-ChildItem -LiteralPath $Target -File -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -notmatch '[\\/]\.(?:index|connector)[\\/]' })
}

function Import-ExtraSignatures {
    # "<sha1> <name>" lines from %APPDATA%\ZoreInspector\signatures.txt and/or the
    # file or URL in ZORE_SIGNATURES. Lets a staff team share hashes of private
    # clients (for example a Prestige build taken from a banned player).
    $sources = @()
    $local = Join-Path (Join-Path $AppData 'ZoreInspector') 'signatures.txt'
    if (Test-Path -LiteralPath $local -PathType Leaf) { $sources += $local }
    if ($env:ZORE_SIGNATURES) { $sources += $env:ZORE_SIGNATURES }
    $count = 0
    foreach ($src in $sources) {
        $lines = @()
        try {
            if ($src -match '^https?://') { $lines = @(([string](Invoke-RestMethod -Uri $src -UserAgent $UserAgent -TimeoutSec 15 -ErrorAction Stop)) -split "`r?`n") }
            else { $lines = @(Get-Content -LiteralPath $src -ErrorAction Stop) }
        } catch { continue }
        foreach ($l in $lines) {
            $m = [regex]::Match(([string]$l).Trim(), '^([0-9a-fA-F]{40})\s+(.+)$')
            if ($m.Success) { $KnownBadHashes[$m.Groups[1].Value.ToLowerInvariant()] = $m.Groups[2].Value.Trim(); $count++ }
        }
    }
    return $count
}

function Start-Inspector {
    Show-Banner

    $instances = Get-MinecraftInstances
    Show-Instances $instances

    $default = $null
    foreach ($i in $instances) {
        if ($i.ModsDir -and (Test-Path -LiteralPath $i.ModsDir)) { $default = $i.ModsDir; break }
    }
    if (-not $default) { $default = Join-Path (Join-Path $AppData '.minecraft') 'mods' }

    $target = Read-TargetPath $default
    if (-not $target) { Write-Host '  Cancelled.' -ForegroundColor DarkGray; return }
    $t0 = Get-Date

    $scanDir = $target
    if (Test-Path -LiteralPath $target -PathType Leaf) { $scanDir = Split-Path $target -Parent }
    $gameStart = $null
    foreach ($i in $instances) { if (Test-SamePath $i.ModsDir $scanDir) { $gameStart = $i.Start; break } }

    Out-Row ''
    Out-Row ('  Scanning: ' + $target) 'White'
    Out-Row ''

    # 1 -- live game ---------------------------------------------------------
    Out-Phase 1 'Inspecting the running game (window, launch arguments, java agents, injected DLLs)'
    $extra = New-Object System.Collections.Generic.List[object]
    foreach ($i in $instances) { Test-Instance $i $extra }
    if ($instances.Count -eq 0) { Out-Done 'skipped - Minecraft is not running' 'Yellow' }
    else { Out-Done ([string]$instances.Count + ' running instance(s) checked') }

    # 2 -- hash + Modrinth ---------------------------------------------------
    Out-Phase 2 'Hashing mods and verifying them with Modrinth'
    $extraSigs = Import-ExtraSignatures
    if ($extraSigs -gt 0) { Out-Done ([string]$extraSigs + ' extra cheat signatures loaded') }
    $results = New-Object System.Collections.Generic.List[object]
    $byPath  = @{}
    foreach ($f in @(Get-ModFiles $target)) {
        if ($JarLikeRx.IsMatch($f.Name)) {
            $results.Add((New-JarResult $f 'Mod')); $byPath[$f.FullName] = $true
        } elseif ($ExecRx.IsMatch($f.Name)) {
            Add-Finding 'SUSPICIOUS' 'Mods folder' ('Program / script file inside the mods folder: ' + $f.Name) $f.FullName
        }
    }
    foreach ($x in $extra) {
        if ($byPath.ContainsKey($x.Path)) { continue }
        try {
            $fi = Get-Item -LiteralPath $x.Path -Force -ErrorAction Stop
            $results.Add((New-JarResult $fi $x.Kind)); $byPath[$fi.FullName] = $true
        } catch { }
    }
    $hashes = @()
    foreach ($r in $results) {
        try { $r.Sha1 = Get-Sha1 $r.Path } catch { $r.OpenError = $_.Exception.Message }
        $src = Get-DownloadSource $r.Path
        if ($src) { $r.Source = $src.Url; $r.Referrer = $src.Referrer }
        if ($r.Sha1 -and $r.Kind -ne 'GameJar') { $hashes += $r.Sha1 }
    }
    $mr = Get-ModrinthInfo $hashes
    $vcount = 0
    foreach ($r in $results) {
        if ($r.Sha1 -and $mr.Map.ContainsKey($r.Sha1)) { $r.Verified = $mr.Map[$r.Sha1]; $vcount++ }
    }
    if ($mr.Online) { Out-Done ([string]$vcount + ' of ' + $results.Count + ' jars are known-good Modrinth files') }
    else { Out-Done ('Modrinth unreachable (' + $mr.Error + ') - every jar gets a deep scan') 'Yellow' }

    # 3 -- deep scan ---------------------------------------------------------
    Out-Phase 3 'Deep-scanning jars (cheat code, 250+ module names, encryption, loaders, disguises, tampered official mods)'
    $k = 0
    foreach ($r in $results) {
        $k++
        Show-Progress $k $results.Count $r.Name
        $deep = ($r.File.Length -le $MaxDeepJar)
        if (-not $r.OpenError) { Invoke-JarScan $r $deep }
    }
    Clear-Progress
    if ($mr.Online) {
        $compared = Test-OfficialCopies $results
        if ($compared -gt 0) { Out-Done ([string]$compared + ' jar(s) compared file-by-file with the official Modrinth release they claim to be') }
    }
    foreach ($r in $results) { Measure-JarResult $r $gameStart }
    Out-Done ([string]@($results | Where-Object { $_.Deep }).Count + ' jars deep-scanned, ' + @($results | Where-Object { $SevRank[$_.Severity] -ge 1 }).Count + ' flagged')

    # 4 -- game memory -------------------------------------------------------
    Out-Phase 4 'Scanning game memory for injected clients (cheat strings, hidden and manually mapped DLLs)'
    if ($instances.Count -eq 0) { Out-Done 'skipped - Minecraft is not running' 'Yellow' }
    elseif (-not $IsWin) { Out-Done 'skipped - Windows only' 'Yellow' }
    else {
        $before = $Z.Findings.Count
        foreach ($i in $instances) {
            if ($i.Limited) { Out-Done ('PID ' + $i.Pid + ': skipped - run as Administrator') 'Yellow'; continue }
            Invoke-MemoryScan $i $results
        }
        Out-Done ([string]@($Z.Findings | Select-Object -Skip $before | Where-Object { $SevRank[$_.Severity] -ge 1 }).Count + ' finding(s)')
    }

    # 5 -- traces + execution history ---------------------------------------
    Out-Phase 5 'Looking for cheat traces (client folders, versions, other instances, Recycle Bin, Downloads, execution history)'
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($cand in @(@($instances | ForEach-Object { $_.GameDir }) + @((Split-Path $scanDir -Parent), (Join-Path $AppData '.minecraft')))) {
        if (-not $cand -or -not (Test-Path -LiteralPath $cand -PathType Container)) { continue }
        $dup = $false
        foreach ($have in $roots) { if (Test-SamePath $have $cand) { $dup = $true; break } }
        if (-not $dup) { $roots.Add($cand) }
    }
    $before = $Z.Findings.Count
    Find-Traces $roots
    Find-OtherInstanceCheats $scanDir
    Find-RecycledFiles
    Find-DownloadedCheats
    [void](Test-ExecutionHistory $instances)
    Out-Done ([string]@($Z.Findings | Select-Object -Skip $before | Where-Object { $SevRank[$_.Severity] -ge 1 }).Count + ' trace(s) found')

    # 6 -- other programs ----------------------------------------------------
    Out-Phase 6 'Checking other running programs (auto-clickers, injectors, ghost-client loaders)'
    $before = $Z.Findings.Count
    Find-SuspiciousPrograms $instances
    Out-Done ([string]($Z.Findings.Count - $before) + ' finding(s)')

    Show-ModResults $results
    Show-Findings
    Show-Summary $results $instances $target ([bool]$mr.Online) ((Get-Date) - $t0)

    Write-Host ''
    Write-Host '  Save this report to your Desktop? (Y/N): ' -ForegroundColor White -NoNewline
    $save = $null
    if ($env:ZORE_SAVE) { $save = $env:ZORE_SAVE; Write-Host $save } else { $save = Read-Host }
    if ($save -match '^(?i)y') {
        $file = Save-Report
        if ($file) { Write-Host ('  Report saved: ' + $file) -ForegroundColor Green }
        else { Write-Host '  Could not save the report.' -ForegroundColor Red }
    }
}

# Relaunch as Administrator (one UAC click) so every check can run.
function Request-Elevation {
    if (-not $IsWin -or $env:ZORE_NO_ELEVATE) { return $false }
    $admin = $false
    try { $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
    if ($admin) { return $false }
    $argLine = $null
    $self = $PSCommandPath
    if ($self -and (Test-Path -LiteralPath $self -PathType Leaf) -and ((Get-Content -LiteralPath $self -TotalCount 3 -ErrorAction SilentlyContinue) -join ' ') -match 'ZORE CLIENT INSPECTOR') {
        $argLine = '-NoProfile -ExecutionPolicy Bypass -File "' + $self + '"'
    } elseif ($ZoreScriptUrl) {
        $argLine = '-NoProfile -ExecutionPolicy Bypass -Command "irm ''' + $ZoreScriptUrl + ''' | iex"'
    }
    if (-not $argLine) { return $false }
    Write-Host ''
    Write-Host '  Zore Client Inspector needs Administrator for the full scan.' -ForegroundColor Yellow
    Write-Host '  Click "Yes" on the Windows prompt - the scan opens in a new window.' -ForegroundColor Yellow
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argLine -ErrorAction Stop
        return $true
    } catch {
        Write-Host '  Not elevated - continuing with a limited scan in this window.' -ForegroundColor DarkYellow
        Start-Sleep -Seconds 2
        return $false
    }
}

if (Request-Elevation) { return }

try {
    Start-Inspector
} catch {
    Write-Host ''
    Write-Host ('  Zore Client Inspector stopped with an error: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host ('  ' + ($_.InvocationInfo.PositionMessage -replace "`n", "`n  ")) -ForegroundColor DarkGray
}

if (-not $env:ZORE_NO_PAUSE) {
    Write-Host ''
    Write-Host '  Press Enter to exit...' -ForegroundColor DarkGray -NoNewline
    try { [void](Read-Host) } catch { }
}

}
