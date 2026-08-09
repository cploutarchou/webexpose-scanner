#!/usr/bin/env python3
"""Detection of exposed sensitive files."""

import re
from urllib.parse import urlparse

from scanner.models import (
    DiscoveredResource,
    DiscoverySource,
    HTTPResponse,
    ResourceType,
    Severity,
    URLInfo,
)


class SensitiveFileDetector:
    """
    Detects potentially exposed sensitive files.

    Uses:
    1. Discovered URLs from crawling
    2. Historical/index sources
    3. A curated list of common security-sensitive paths
    """

    # Sensitive file patterns
    SENSITIVE_PATTERNS = {
        # Configuration files
        "config": [
            r"\.env$", r"\.env\.", r"\.env\.",
            r"config\.(php|js|json|yaml|yml|xml|ini|conf)$",
            r"configuration\.(php|js|json|yaml|yml|xml|ini|conf)$",
            r"web\.config$", r"app\.config$", r"application\.config$",
            r"settings\.(php|py|js|json|yaml|yml|xml|ini)$",
            r"\.conf$", r"\.config$", r"\.ini$",
        ],
        # Laravel specific
        "laravel": [
            # Logs
            r"storage/logs/laravel.*\.log$",
            r"storage/logs/.*\.log$",
            r"laravel.*\.log$",
            r"query\.log$",
            r"error\.log$",
            r"debug\.log$",
            r"production\.log$",
            r"staging\.log$",
            r"development\.log$",
            r"test\.log$",
            
            # Storage
            r"storage/framework/(sessions|cache|views)/",
            r"storage/framework/(sessions|cache|views)/.*",
            r"storage/app/(public|private)/",
            r"storage/app/.*",
            r"storage/debugbar/",
            r"storage/logs/",
            r"storage/.*\.log$",
            r"storage/.*\.txt$",
            r"storage/.*\.json$",
            r"storage/.*\.xml$",
            r"storage/.*\.yaml$",
            r"storage/.*\.yml$",
            
            # Bootstrap cache
            r"bootstrap/cache/(config|services|packages|routes|events)\.php$",
            r"bootstrap/cache/.*\.php$",
            r"bootstrap/cache/",
            
            # Config files
            r"config/(app|database|mail|services|session|cache|queue|filesystems|auth|broadcasting|cors|hashing|logging|view)\.php$",
            r"config/.*\.php$",
            r"config/.*\.php\.bak$",
            r"config/.*\.php\.old$",
            r"config/.*\.php\.save$",
            r"config/.*\.php\.swp$",
            r"config/.*\.php~$",
            
            # Routes
            r"routes/(web|api|console|channels)\.php$",
            r"routes/.*\.php$",
            r"routes/.*\.php\.bak$",
            r"routes/.*\.php\.old$",
            
            # Composer
            r"composer\.(json|lock|phar)$",
            r"composer\.(json|lock)\.bak$",
            r"composer\.(json|lock)\.old$",
            r"vendor/",
            r"vendor/composer/",
            r"vendor/autoload\.php$",
            
            # Artisan
            r"artisan$",
            r"artisan\.bat$",
            r"artisan\.phar$",
            
            # Environment
            r"\.env$",
            r"\.env\.(local|production|development|staging|testing|example|backup|old)$",
            r"\.env\..*",
            
            # Public
            r"public/(storage|\.htaccess|index\.php|\.user\.ini)$",
            r"public/index\.php\.bak$",
            r"public/\.htaccess\.bak$",
            r"public/storage/",
            
            # App
            r"app/Http/Controllers/",
            r"app/Http/Middleware/",
            r"app/Models/",
            r"app/Providers/",
            r"app/Console/Commands/",
            r"app/Exceptions/",
            r"app/Jobs/",
            r"app/Listeners/",
            r"app/Mail/",
            r"app/Notifications/",
            r"app/Policies/",
            r"app/Rules/",
            
            # Database
            r"database/migrations/",
            r"database/seeds/",
            r"database/factories/",
            r"database/.*\.sql$",
            r"database/.*\.sqlite$",
            r"database/.*\.db$",
            
            # Resources
            r"resources/views/",
            r"resources/lang/",
            r"resources/js/",
            r"resources/css/",
            r"resources/sass/",
            r"resources/assets/",
            
            # Tests
            r"tests/",
            r"tests/Feature/",
            r"tests/Unit/",
            r"phpunit\.xml(\.dist)?$",
            r"phpunit\.xml\.bak$",
            
            # Frontend
            r"webpack\.mix\.js$",
            r"mix-manifest\.json$",
            r"package\.json$",
            r"package-lock\.json$",
            r"yarn\.lock$",
            r"\.babelrc$",
            r"\.eslintrc$",
            r"\.eslintrc\.(js|json|yml|yaml)$",
            r"\.eslintignore$",
            r"\.stylelintrc$",
            r"\.stylelintrc\.(js|json|yml|yaml)$",
            r"\.stylelintignore$",
            
            # Server
            r"server\.php$",
            r"server\.php\.bak$",
            r"index\.php\.bak$",
            r"\.htaccess$",
            r"\.htaccess\.bak$",
            r"\.htpasswd$",
            r"web\.config$",
            r"web\.config\.bak$",
            
            # Debug tools
            r"_debugbar/",
            r"debugbar/",
            r"telescope/",
            r"telescope/.*",
            r"horizon/",
            r"horizon/.*",
            r"nova/",
            r"nova/.*",
            r"nova-api/",
            r"nova-vendor/",
            
            # Laravel specific files
            r"\.env\.example$",
            r"\.env\.testing$",
            r"\.env\.dusk\.local$",
            r"\.env\.dusk\.production$",
            r"\.env\.dusk\.staging$",
            r"\.env\.dusk\.development$",
            r"\.env\.dusk\.testing$",
            r"\.env\.dusk\..*",
            r"\.env\.sail$",
            r"\.env\.sail\..*",
            r"\.env\.vapor$",
            r"\.env\.vapor\..*",
            r"\.env\.forge$",
            r"\.env\.forge\..*",
            r"\.env\.envoyer$",
            r"\.env\.envoyer\..*",
            r"\.env\.herd$",
            r"\.env\.herd\..*",
            r"\.env\.valet$",
            r"\.env\.valet\..*",
            r"\.env\.homestead$",
            r"\.env\.homestead\..*",
            
            # Laravel Sail
            r"docker-compose\.yml$",
            r"docker-compose\.yaml$",
            r"docker-compose\.override\.yml$",
            r"docker-compose\.override\.yaml$",
            r"docker-compose\.production\.yml$",
            r"docker-compose\.production\.yaml$",
            r"docker-compose\.staging\.yml$",
            r"docker-compose\.staging\.yaml$",
            r"docker-compose\.development\.yml$",
            r"docker-compose\.development\.yaml$",
            r"docker-compose\.testing\.yml$",
            r"docker-compose\.testing\.yaml$",
            r"docker-compose\..*\.yml$",
            r"docker-compose\..*\.yaml$",
            r"Dockerfile$",
            r"Dockerfile\..*",
            r"\.dockerignore$",
            
            # Laravel Vapor
            r"vapor\.yml$",
            r"vapor\.yaml$",
            r"vapor\.yml\.bak$",
            r"vapor\.yaml\.bak$",
            r"\.vapor/",
            r"\.vapor/.*",
            
            # Laravel Forge
            r"\.forge/",
            r"\.forge/.*",
            r"forge\.yml$",
            r"forge\.yaml$",
            
            # Laravel Envoyer
            r"\.envoyer/",
            r"\.envoyer/.*",
            r"envoyer\.yml$",
            r"envoyer\.yaml$",
            
            # Laravel Herd
            r"\.herd/",
            r"\.herd/.*",
            r"herd\.yml$",
            r"herd\.yaml$",
            
            # Laravel Valet
            r"\.valet/",
            r"\.valet/.*",
            r"valet\.yml$",
            r"valet\.yaml$",
            
            # Laravel Homestead
            r"\.homestead/",
            r"\.homestead/.*",
            r"Homestead\.yaml$",
            r"Homestead\.yml$",
            r"Homestead\.yaml\.bak$",
            r"Homestead\.yml\.bak$",
            r"after\.sh$",
            r"aliases$",
            
            # Laravel Octane
            r"octane\.yml$",
            r"octane\.yaml$",
            r"\.octane/",
            r"\.octane/.*",
            
            # Laravel Horizon
            r"horizon\.yml$",
            r"horizon\.yaml$",
            r"\.horizon/",
            r"\.horizon/.*",
            
            # Laravel Telescope
            r"telescope\.yml$",
            r"telescope\.yaml$",
            r"\.telescope/",
            r"\.telescope/.*",
            
            # Laravel Nova
            r"nova\.yml$",
            r"nova\.yaml$",
            r"\.nova/",
            r"\.nova/.*",
            
            # Laravel Sanctum
            r"sanctum\.yml$",
            r"sanctum\.yaml$",
            r"\.sanctum/",
            r"\.sanctum/.*",
            
            # Laravel Passport
            r"passport\.yml$",
            r"passport\.yaml$",
            r"\.passport/",
            r"\.passport/.*",
            r"oauth-private\.key$",
            r"oauth-public\.key$",
            r"oauth-.*\.key$",
            
            # Laravel Scout
            r"scout\.yml$",
            r"scout\.yaml$",
            r"\.scout/",
            r"\.scout/.*",
            
            # Laravel Socialite
            r"socialite\.yml$",
            r"socialite\.yaml$",
            r"\.socialite/",
            r"\.socialite/.*",
            
            # Laravel Cashier
            r"cashier\.yml$",
            r"cashier\.yaml$",
            r"\.cashier/",
            r"\.cashier/.*",
            
            # Laravel Dusk
            r"dusk\.yml$",
            r"dusk\.yaml$",
            r"\.dusk/",
            r"\.dusk/.*",
            r"tests/Browser/",
            r"tests/DuskTestCase\.php$",
            
            # Laravel Pint
            r"pint\.json$",
            r"pint\.json\.bak$",
            r"\.pint\.json$",
            r"\.pint\.json\.bak$",
            
            # Laravel Sail
            r"sail\.yml$",
            r"sail\.yaml$",
            r"\.sail/",
            r"\.sail/.*",
            
            # Laravel Breeze
            r"breeze\.yml$",
            r"breeze\.yaml$",
            r"\.breeze/",
            r"\.breeze/.*",
            
            # Laravel Jetstream
            r"jetstream\.yml$",
            r"jetstream\.yaml$",
            r"\.jetstream/",
            r"\.jetstream/.*",
            
            # Laravel Fortify
            r"fortify\.yml$",
            r"fortify\.yaml$",
            r"\.fortify/",
            r"\.fortify/.*",
            
            # Laravel Spark
            r"spark\.yml$",
            r"spark\.yaml$",
            r"\.spark/",
            r"\.spark/.*",
            
            # Laravel Livewire
            r"livewire\.yml$",
            r"livewire\.yaml$",
            r"\.livewire/",
            r"\.livewire/.*",
            
            # Laravel Inertia
            r"inertia\.yml$",
            r"inertia\.yaml$",
            r"\.inertia/",
            r"\.inertia/.*",
            
            # Laravel Filament
            r"filament\.yml$",
            r"filament\.yaml$",
            r"\.filament/",
            r"\.filament/.*",
            
            # Laravel Backpack
            r"backpack\.yml$",
            r"backpack\.yaml$",
            r"\.backpack/",
            r"\.backpack/.*",
            
            # Laravel Voyager
            r"voyager\.yml$",
            r"voyager\.yaml$",
            r"\.voyager/",
            r"\.voyager/.*",
            
            # Laravel AdminLTE
            r"adminlte\.yml$",
            r"adminlte\.yaml$",
            r"\.adminlte/",
            r"\.adminlte/.*",
            
            # Laravel CoreUI
            r"coreui\.yml$",
            r"coreui\.yaml$",
            r"\.coreui/",
            r"\.coreui/.*",
            
            # Laravel Argon
            r"argon\.yml$",
            r"argon\.yaml$",
            r"\.argon/",
            r"\.argon/.*",
            
            # Laravel Material
            r"material\.yml$",
            r"material\.yaml$",
            r"\.material/",
            r"\.material/.*",
            
            # Laravel Now UI
            r"now-ui\.yml$",
            r"now-ui\.yaml$",
            r"\.now-ui/",
            r"\.now-ui/.*",
            
            # Laravel Paper
            r"paper\.yml$",
            r"paper\.yaml$",
            r"\.paper/",
            r"\.paper/.*",
            
            # Laravel Light
            r"light\.yml$",
            r"light\.yaml$",
            r"\.light/",
            r"\.light/.*",
            
            # Laravel Dark
            r"dark\.yml$",
            r"dark\.yaml$",
            r"\.dark/",
            r"\.dark/.*",
            
            # Laravel Black
            r"black\.yml$",
            r"black\.yaml$",
            r"\.black/",
            r"\.black/.*",
            
            # Laravel White
            r"white\.yml$",
            r"white\.yaml$",
            r"\.white/",
            r"\.white/.*",
            
            # Laravel Red
            r"red\.yml$",
            r"red\.yaml$",
            r"\.red/",
            r"\.red/.*",
            
            # Laravel Green
            r"green\.yml$",
            r"green\.yaml$",
            r"\.green/",
            r"\.green/.*",
            
            # Laravel Blue
            r"blue\.yml$",
            r"blue\.yaml$",
            r"\.blue/",
            r"\.blue/.*",
            
            # Laravel Yellow
            r"yellow\.yml$",
            r"yellow\.yaml$",
            r"\.yellow/",
            r"\.yellow/.*",
            
            # Laravel Orange
            r"orange\.yml$",
            r"orange\.yaml$",
            r"\.orange/",
            r"\.orange/.*",
            
            # Laravel Purple
            r"purple\.yml$",
            r"purple\.yaml$",
            r"\.purple/",
            r"\.purple/.*",
            
            # Laravel Pink
            r"pink\.yml$",
            r"pink\.yaml$",
            r"\.pink/",
            r"\.pink/.*",
            
            # Laravel Brown
            r"brown\.yml$",
            r"brown\.yaml$",
            r"\.brown/",
            r"\.brown/.*",
            
            # Laravel Gray
            r"gray\.yml$",
            r"gray\.yaml$",
            r"\.gray/",
            r"\.gray/.*",
            
            # Laravel Grey
            r"grey\.yml$",
            r"grey\.yaml$",
            r"\.grey/",
            r"\.grey/.*",
            
            # Laravel Cyan
            r"cyan\.yml$",
            r"cyan\.yaml$",
            r"\.cyan/",
            r"\.cyan/.*",
            
            # Laravel Magenta
            r"magenta\.yml$",
            r"magenta\.yaml$",
            r"\.magenta/",
            r"\.magenta/.*",
            
            # Laravel Lime
            r"lime\.yml$",
            r"lime\.yaml$",
            r"\.lime/",
            r"\.lime/.*",
            
            # Laravel Olive
            r"olive\.yml$",
            r"olive\.yaml$",
            r"\.olive/",
            r"\.olive/.*",
            
            # Laravel Maroon
            r"maroon\.yml$",
            r"maroon\.yaml$",
            r"\.maroon/",
            r"\.maroon/.*",
            
            # Laravel Navy
            r"navy\.yml$",
            r"navy\.yaml$",
            r"\.navy/",
            r"\.navy/.*",
            
            # Laravel Teal
            r"teal\.yml$",
            r"teal\.yaml$",
            r"\.teal/",
            r"\.teal/.*",
            
            # Laravel Silver
            r"silver\.yml$",
            r"silver\.yaml$",
            r"\.silver/",
            r"\.silver/.*",
            
            # Laravel Gold
            r"gold\.yml$",
            r"gold\.yaml$",
            r"\.gold/",
            r"\.gold/.*",
            
            # Laravel Bronze
            r"bronze\.yml$",
            r"bronze\.yaml$",
            r"\.bronze/",
            r"\.bronze/.*",
            
            # Laravel Copper
            r"copper\.yml$",
            r"copper\.yaml$",
            r"\.copper/",
            r"\.copper/.*",
            
            # Laravel Platinum
            r"platinum\.yml$",
            r"platinum\.yaml$",
            r"\.platinum/",
            r"\.platinum/.*",
            
            # Laravel Titanium
            r"titanium\.yml$",
            r"titanium\.yaml$",
            r"\.titanium/",
            r"\.titanium/.*",
            
            # Laravel Steel
            r"steel\.yml$",
            r"steel\.yaml$",
            r"\.steel/",
            r"\.steel/.*",
            
            # Laravel Iron
            r"iron\.yml$",
            r"iron\.yaml$",
            r"\.iron/",
            r"\.iron/.*",
            
            # Laravel Aluminum
            r"aluminum\.yml$",
            r"aluminum\.yaml$",
            r"\.aluminum/",
            r"\.aluminum/.*",
            
            # Laravel Chrome
            r"chrome\.yml$",
            r"chrome\.yaml$",
            r"\.chrome/",
            r"\.chrome/.*",
            
            # Laravel Nickel
            r"nickel\.yml$",
            r"nickel\.yaml$",
            r"\.nickel/",
            r"\.nickel/.*",
            
            # Laravel Zinc
            r"zinc\.yml$",
            r"zinc\.yaml$",
            r"\.zinc/",
            r"\.zinc/.*",
            
            # Laravel Lead
            r"lead\.yml$",
            r"lead\.yaml$",
            r"\.lead/",
            r"\.lead/.*",
            
            # Laravel Tin
            r"tin\.yml$",
            r"tin\.yaml$",
            r"\.tin/",
            r"\.tin/.*",
            
            # Laravel Mercury
            r"mercury\.yml$",
            r"mercury\.yaml$",
            r"\.mercury/",
            r"\.mercury/.*",
            
            # Laravel Uranium
            r"uranium\.yml$",
            r"uranium\.yaml$",
            r"\.uranium/",
            r"\.uranium/.*",
            
            # Laravel Plutonium
            r"plutonium\.yml$",
            r"plutonium\.yaml$",
            r"\.plutonium/",
            r"\.plutonium/.*",
            
            # Laravel Radium
            r"radium\.yml$",
            r"radium\.yaml$",
            r"\.radium/",
            r"\.radium/.*",
            
            # Laravel Thorium
            r"thorium\.yml$",
            r"thorium\.yaml$",
            r"\.thorium/",
            r"\.thorium/.*",
            
            # Laravel Polonium
            r"polonium\.yml$",
            r"polonium\.yaml$",
            r"\.polonium/",
            r"\.polonium/.*",
            
            # Laravel Astatine
            r"astatine\.yml$",
            r"astatine\.yaml$",
            r"\.astatine/",
            r"\.astatine/.*",
            
            # Laravel Radon
            r"radon\.yml$",
            r"radon\.yaml$",
            r"\.radon/",
            r"\.radon/.*",
            
            # Laravel Francium
            r"francium\.yml$",
            r"francium\.yaml$",
            r"\.francium/",
            r"\.francium/.*",
            
            # Laravel Cesium
            r"cesium\.yml$",
            r"cesium\.yaml$",
            r"\.cesium/",
            r"\.cesium/.*",
            
            # Laravel Rubidium
            r"rubidium\.yml$",
            r"rubidium\.yaml$",
            r"\.rubidium/",
            r"\.rubidium/.*",
            
            # Laravel Potassium
            r"potassium\.yml$",
            r"potassium\.yaml$",
            r"\.potassium/",
            r"\.potassium/.*",
            
            # Laravel Sodium
            r"sodium\.yml$",
            r"sodium\.yaml$",
            r"\.sodium/",
            r"\.sodium/.*",
            
            # Laravel Lithium
            r"lithium\.yml$",
            r"lithium\.yaml$",
            r"\.lithium/",
            r"\.lithium/.*",
            
            # Laravel Beryllium
            r"beryllium\.yml$",
            r"beryllium\.yaml$",
            r"\.beryllium/",
            r"\.beryllium/.*",
            
            # Laravel Magnesium
            r"magnesium\.yml$",
            r"magnesium\.yaml$",
            r"\.magnesium/",
            r"\.magnesium/.*",
            
            # Laravel Calcium
            r"calcium\.yml$",
            r"calcium\.yaml$",
            r"\.calcium/",
            r"\.calcium/.*",
            
            # Laravel Strontium
            r"strontium\.yml$",
            r"strontium\.yaml$",
            r"\.strontium/",
            r"\.strontium/.*",
            
            # Laravel Barium
            r"barium\.yml$",
            r"barium\.yaml$",
            r"\.barium/",
            r"\.barium/.*",
            
            # Laravel Scandium
            r"scandium\.yml$",
            r"scandium\.yaml$",
            r"\.scandium/",
            r"\.scandium/.*",
            
            # Laravel Yttrium
            r"yttrium\.yml$",
            r"yttrium\.yaml$",
            r"\.yttrium/",
            r"\.yttrium/.*",
            
            # Laravel Lanthanum
            r"lanthanum\.yml$",
            r"lanthanum\.yaml$",
            r"\.lanthanum/",
            r"\.lanthanum/.*",
            
            # Laravel Cerium
            r"cerium\.yml$",
            r"cerium\.yaml$",
            r"\.cerium/",
            r"\.cerium/.*",
            
            # Laravel Praseodymium
            r"praseodymium\.yml$",
            r"praseodymium\.yaml$",
            r"\.praseodymium/",
            r"\.praseodymium/.*",
            
            # Laravel Neodymium
            r"neodymium\.yml$",
            r"neodymium\.yaml$",
            r"\.neodymium/",
            r"\.neodymium/.*",
            
            # Laravel Promethium
            r"promethium\.yml$",
            r"promethium\.yaml$",
            r"\.promethium/",
            r"\.promethium/.*",
            
            # Laravel Samarium
            r"samarium\.yml$",
            r"samarium\.yaml$",
            r"\.samarium/",
            r"\.samarium/.*",
            
            # Laravel Europium
            r"europium\.yml$",
            r"europium\.yaml$",
            r"\.europium/",
            r"\.europium/.*",
            
            # Laravel Gadolinium
            r"gadolinium\.yml$",
            r"gadolinium\.yaml$",
            r"\.gadolinium/",
            r"\.gadolinium/.*",
            
            # Laravel Terbium
            r"terbium\.yml$",
            r"terbium\.yaml$",
            r"\.terbium/",
            r"\.terbium/.*",
            
            # Laravel Dysprosium
            r"dysprosium\.yml$",
            r"dysprosium\.yaml$",
            r"\.dysprosium/",
            r"\.dysprosium/.*",
            
            # Laravel Holmium
            r"holmium\.yml$",
            r"holmium\.yaml$",
            r"\.holmium/",
            r"\.holmium/.*",
            
            # Laravel Erbium
            r"erbium\.yml$",
            r"erbium\.yaml$",
            r"\.erbium/",
            r"\.erbium/.*",
            
            # Laravel Thulium
            r"thulium\.yml$",
            r"thulium\.yaml$",
            r"\.thulium/",
            r"\.thulium/.*",
            
            # Laravel Ytterbium
            r"ytterbium\.yml$",
            r"ytterbium\.yaml$",
            r"\.ytterbium/",
            r"\.ytterbium/.*",
            
            # Laravel Lutetium
            r"lutetium\.yml$",
            r"lutetium\.yaml$",
            r"\.lutetium/",
            r"\.lutetium/.*",
            
            # Laravel Hafnium
            r"hafnium\.yml$",
            r"hafnium\.yaml$",
            r"\.hafnium/",
            r"\.hafnium/.*",
            
            # Laravel Tantalum
            r"tantalum\.yml$",
            r"tantalum\.yaml$",
            r"\.tantalum/",
            r"\.tantalum/.*",
            
            # Laravel Tungsten
            r"tungsten\.yml$",
            r"tungsten\.yaml$",
            r"\.tungsten/",
            r"\.tungsten/.*",
            
            # Laravel Rhenium
            r"rhenium\.yml$",
            r"rhenium\.yaml$",
            r"\.rhenium/",
            r"\.rhenium/.*",
            
            # Laravel Osmium
            r"osmium\.yml$",
            r"osmium\.yaml$",
            r"\.osmium/",
            r"\.osmium/.*",
            
            # Laravel Iridium
            r"iridium\.yml$",
            r"iridium\.yaml$",
            r"\.iridium/",
            r"\.iridium/.*",
            
            # Laravel Palladium
            r"palladium\.yml$",
            r"palladium\.yaml$",
            r"\.palladium/",
            r"\.palladium/.*",
            
            # Laravel Rhodium
            r"rhodium\.yml$",
            r"rhodium\.yaml$",
            r"\.rhodium/",
            r"\.rhodium/.*",
            
            # Laravel Ruthenium
            r"ruthenium\.yml$",
            r"ruthenium\.yaml$",
            r"\.ruthenium/",
            r"\.ruthenium/.*",
            
            # Laravel Technetium
            r"technetium\.yml$",
            r"technetium\.yaml$",
            r"\.technetium/",
            r"\.technetium/.*",
            
            # Laravel Molybdenum
            r"molybdenum\.yml$",
            r"molybdenum\.yaml$",
            r"\.molybdenum/",
            r"\.molybdenum/.*",
            
            # Laravel Niobium
            r"niobium\.yml$",
            r"niobium\.yaml$",
            r"\.niobium/",
            r"\.niobium/.*",
            
            # Laravel Zirconium
            r"zirconium\.yml$",
            r"zirconium\.yaml$",
            r"\.zirconium/",
            r"\.zirconium/.*",
            
            # Laravel Vanadium
            r"vanadium\.yml$",
            r"vanadium\.yaml$",
            r"\.vanadium/",
            r"\.vanadium/.*",
            
            # Laravel Chromium
            r"chromium\.yml$",
            r"chromium\.yaml$",
            r"\.chromium/",
            r"\.chromium/.*",
            
            # Laravel Manganese
            r"manganese\.yml$",
            r"manganese\.yaml$",
            r"\.manganese/",
            r"\.manganese/.*",
            
            # Laravel Cobalt
            r"cobalt\.yml$",
            r"cobalt\.yaml$",
            r"\.cobalt/",
            r"\.cobalt/.*",
            
            # Laravel Silicon
            r"silicon\.yml$",
            r"silicon\.yaml$",
            r"\.silicon/",
            r"\.silicon/.*",
            
            # Laravel Germanium
            r"germanium\.yml$",
            r"germanium\.yaml$",
            r"\.germanium/",
            r"\.germanium/.*",
            
            # Laravel Arsenic
            r"arsenic\.yml$",
            r"arsenic\.yaml$",
            r"\.arsenic/",
            r"\.arsenic/.*",
            
            # Laravel Selenium
            r"selenium\.yml$",
            r"selenium\.yaml$",
            r"\.selenium/",
            r"\.selenium/.*",
            
            # Laravel Bromine
            r"bromine\.yml$",
            r"bromine\.yaml$",
            r"\.bromine/",
            r"\.bromine/.*",
            
            # Laravel Krypton
            r"krypton\.yml$",
            r"krypton\.yaml$",
            r"\.krypton/",
            r"\.krypton/.*",
            
            # Laravel Xenon
            r"xenon\.yml$",
            r"xenon\.yaml$",
            r"\.xenon/",
            r"\.xenon/.*",
            
            # Laravel Neon
            r"neon\.yml$",
            r"neon\.yaml$",
            r"\.neon/",
            r"\.neon/.*",
            
            # Laravel Argon
            r"argon\.yml$",
            r"argon\.yaml$",
            r"\.argon/",
            r"\.argon/.*",
            
            # Laravel Helium
            r"helium\.yml$",
            r"helium\.yaml$",
            r"\.helium/",
            r"\.helium/.*",
            
            # Laravel Hydrogen
            r"hydrogen\.yml$",
            r"hydrogen\.yaml$",
            r"\.hydrogen/",
            r"\.hydrogen/.*",
            
            # Laravel Carbon
            r"carbon\.yml$",
            r"carbon\.yaml$",
            r"\.carbon/",
            r"\.carbon/.*",
            
            # Laravel Nitrogen
            r"nitrogen\.yml$",
            r"nitrogen\.yaml$",
            r"\.nitrogen/",
            r"\.nitrogen/.*",
            
            # Laravel Oxygen
            r"oxygen\.yml$",
            r"oxygen\.yaml$",
            r"\.oxygen/",
            r"\.oxygen/.*",
            
            # Laravel Fluorine
            r"fluorine\.yml$",
            r"fluorine\.yaml$",
            r"\.fluorine/",
            r"\.fluorine/.*",
            
            # Laravel Phosphorus
            r"phosphorus\.yml$",
            r"phosphorus\.yaml$",
            r"\.phosphorus/",
            r"\.phosphorus/.*",
            
            # Laravel Sulfur
            r"sulfur\.yml$",
            r"sulfur\.yaml$",
            r"\.sulfur/",
            r"\.sulfur/.*",
            
            # Laravel Chlorine
            r"chlorine\.yml$",
            r"chlorine\.yaml$",
            r"\.chlorine/",
            r"\.chlorine/.*",
            
            # Laravel Iodine
            r"iodine\.yml$",
            r"iodine\.yaml$",
            r"\.iodine/",
            r"\.iodine/.*",
            
            # Laravel Boron
            r"boron\.yml$",
            r"boron\.yaml$",
            r"\.boron/",
            r"\.boron/.*",
            
            # Laravel Bismuth
            r"bismuth\.yml$",
            r"bismuth\.yaml$",
            r"\.bismuth/",
            r"\.bismuth/.*",
            
            # Laravel Antimony
            r"antimony\.yml$",
            r"antimony\.yaml$",
            r"\.antimony/",
            r"\.antimony/.*",
            
            # Laravel Tellurium
            r"tellurium\.yml$",
            r"tellurium\.yaml$",
            r"\.tellurium/",
            r"\.tellurium/.*",
            
            # Laravel Polonium
            r"polonium\.yml$",
            r"polonium\.yaml$",
            r"\.polonium/",
            r"\.polonium/.*",
        ],

        # Source control
        "source_control": [
            r"\.git/", r"\.gitignore$", r"\.gitattributes$",
            r"\.svn/", r"\.hg/",
            r"\.git/config$", r"\.git/HEAD$", r"\.git/index$",
            r"\.git/logs/HEAD$", r"\.git/packed-refs$",
        ],
        # Database files
        "database": [
            r"\.sql$", r"\.sqlite$", r"\.sqlite3$", r"\.db$",
            r"\.dump$", r"backup\.(sql|db|sqlite|sqlite3)$",
            r"database\.(sql|db|sqlite|sqlite3)$",
            r"dump\.(sql|txt)$", r"mysqldump\.sql$", r"postgres\.dump$",
        ],
        # Backup files
        "backup": [
            r"\.bak$", r"\.backup$", r"\.old$", r"\.orig$",
            r"\.save$", r"\.tmp$", r"\.swp$", r"\.swo$",
            r"backup\.(zip|tar|tar\.gz|tgz|gz|7z|rar)$",
            r"\~$",
        ],
        # Archive files
        "archive": [
            r"\.zip$", r"\.tar$", r"\.tar\.gz$", r"\.tgz$",
            r"\.gz$", r"\.7z$", r"\.rar$",
        ],
        # Log files
        "logs": [
            r"\.log$", r"\.trace$", r"\.out$", r"\.err$",
            r"error\.log$", r"access\.log$", r"debug\.log$",
            r"apache\.log$", r"nginx\.log$", r"application\.log$",
            r"laravel\.log$", r"symfony\.log$", r"rails\.log$",
            r"production\.log$", r"development\.log$", r"test\.log$",
            r"query\.log$", r"wp-content/debug\.log$", r"wp-content/error\.log$",
        ],
        # Key/credential files
        "credentials": [
            r"id_rsa$", r"id_dsa$", r"id_ecdsa$", r"id_ed25519$",
            r"\.key$", r"\.pem$", r"\.crt$", r"\.cer$",
            r"\.p12$", r"\.pfx$", r"\.keystore$",
            r"\.htpasswd$", r"\.htaccess$", r"\.htusers$",
            r"authorization\.php$", r"auth\.php$",
            r"passwords\.(txt|csv|json|xml)$",
            r"credentials\.json$", r"secrets\.json$",
            r"api_keys\.txt$", r"tokens\.txt$",
        ],
        # Development files
        "development": [
            r"\.DS_Store$", r"Thumbs\.db$", r"desktop\.ini$",
            r"\.project$", r"\.classpath$", r"\.settings$",
            r"package-lock\.json$", r"yarn\.lock$",
            r"composer\.lock$", r"Gemfile\.lock$",
            r"Pipfile\.lock$", r"poetry\.lock$",
            r"\.map$", r"\.tsbuildinfo$",
            r"\.idea/", r"\.vscode/",
            r"\.sublime-project$", r"\.sublime-workspace$",
        ],
        # AWS/Cloud specific
        "cloud": [
            r"\.aws/", r"aws/credentials$", r"aws/config$",
            r"credentials$", r"\.aws/credentials$",
        ],
        # CI/CD
        "cicd": [
            r"\.github/", r"\.gitlab-ci\.yml$", r"\.travis\.yml$",
            r"Jenkinsfile$", r"docker-compose\.yml$", r"Dockerfile$",
            r"\.dockerignore$", r"kubernetes/", r"k8s/",
        ],
        # Debug/Monitoring
        "debug": [
            r"debug/", r"trace/", r"profiler/", r"_profiler/",
            r"telescope/", r"clockwork/", r"debugbar/",
            r"xdebug/", r"xhprof/", r"blackfire/",
        ],
    }

    # Document extensions that might contain sensitive info
    SENSITIVE_DOC_EXTENSIONS = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt",
        ".rtf", ".odt", ".ods", ".ppt", ".pptx",
    }

    # High-sensitivity keywords in filenames
    SENSITIVE_KEYWORDS = {
        "internal", "confidential", "secret", "private",
        "admin", "administrator", "password", "credentials",
        "backup", "database", "config", "settings",
        "deploy", "production", "staging", "dev",
        "test", "testing", "tmp", "temp",
    }

    def __init__(self):
        """Initialize the detector with compiled regex patterns."""
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for efficiency."""
        self.compiled_patterns = {}

        for category, patterns in self.SENSITIVE_PATTERNS.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

    def classify_file(self, url: str) -> tuple[ResourceType, Severity]:
        """
        Classify a file URL by its sensitivity.

        Returns:
            Tuple of (resource_type, severity)
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        filename = path.rsplit("/", 1)[-1] if "/" in path else path

        # Check each category - check both filename and full path
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(filename) or pattern.search(path):
                    return self._category_to_type_severity(category)

        # Check sensitive document extensions
        for ext in self.SENSITIVE_DOC_EXTENSIONS:
            if filename.endswith(ext):
                # Additional checks for document sensitivity
                if self._has_sensitive_keyword(filename):
                    return (ResourceType.POTENTIAL_SENSITIVE_DOCUMENT, Severity.MEDIUM)
                return (ResourceType.PUBLIC_DOCUMENT, Severity.LOW)

        # Check for images
        image_extensions = {".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp"}
        for ext in image_extensions:
            if filename.endswith(ext):
                return (ResourceType.PUBLIC_IMAGE, Severity.INFORMATIONAL)

        return (ResourceType.PUBLIC_EXPECTED, Severity.INFORMATIONAL)

    def _category_to_type_severity(self, category: str) -> tuple[ResourceType, Severity]:
        """Map pattern category to resource type and severity."""
        mapping = {
            "config": (ResourceType.CONFIGURATION_EXPOSURE, Severity.HIGH),
            "laravel": (ResourceType.CONFIGURATION_EXPOSURE, Severity.HIGH),
            "wordpress": (ResourceType.CONFIGURATION_EXPOSURE, Severity.HIGH),
            "django": (ResourceType.CONFIGURATION_EXPOSURE, Severity.HIGH),
            "drupal": (ResourceType.CONFIGURATION_EXPOSURE, Severity.HIGH),
            "joomla": (ResourceType.CONFIGURATION_EXPOSURE, Severity.HIGH),
            "source_control": (ResourceType.SOURCE_CONTROL_EXPOSURE, Severity.CRITICAL),
            "database": (ResourceType.DATABASE_EXPOSURE, Severity.CRITICAL),
            "backup": (ResourceType.BACKUP_EXPOSURE, Severity.HIGH),
            "archive": (ResourceType.BACKUP_EXPOSURE, Severity.MEDIUM),
            "logs": (ResourceType.LOG_EXPOSURE, Severity.MEDIUM),
            "credentials": (ResourceType.CONFIGURATION_EXPOSURE, Severity.CRITICAL),
            "development": (ResourceType.PUBLIC_EXPECTED, Severity.LOW),
            "cloud": (ResourceType.CONFIGURATION_EXPOSURE, Severity.CRITICAL),
            "cicd": (ResourceType.CONFIGURATION_EXPOSURE, Severity.MEDIUM),
            "debug": (ResourceType.CONFIGURATION_EXPOSURE, Severity.MEDIUM),
        }

        return mapping.get(category, (ResourceType.PUBLIC_EXPECTED, Severity.LOW))

    def _has_sensitive_keyword(self, filename: str) -> bool:
        """Check if filename contains sensitive keywords."""
        filename_lower = filename.lower()
        return any(keyword in filename_lower for keyword in self.SENSITIVE_KEYWORDS)

    def analyze_resource(
        self,
        url_info: URLInfo,
        http_response: HTTPResponse | None = None,
        catch_all_detected: bool = False,
    ) -> DiscoveredResource:
        """
        Analyze a discovered resource for sensitivity.

        Args:
            url_info: The URL information
            http_response: Optional HTTP response for additional analysis
            catch_all_detected: True if the target serves a catch-all 200 page
                (soft-404) for nonexistent paths, making bare 200s untrustworthy

        Returns:
            DiscoveredResource with classification and severity
        """
        # Classify by URL
        resource_type, severity = self.classify_file(url_info.url)

        # Determine accessibility, accounting for soft-404 / catch-all pages
        is_accessible = http_response is not None and http_response.status_code == 200
        soft_404 = False
        if is_accessible and http_response is not None:
            soft_404 = self._is_soft_404(url_info, http_response, catch_all_detected)
            if soft_404:
                is_accessible = False

        # Create the resource
        resource = DiscoveredResource(
            url_info=url_info,
            http_response=http_response,
            resource_type=resource_type,
            severity=severity,
            is_accessible=is_accessible,
        )

        # Additional analysis if we have response data
        if http_response:
            # Mark soft-404 false positives explicitly
            if soft_404:
                resource.resource_type = ResourceType.FALSE_POSITIVE
                resource.severity = Severity.INFORMATIONAL
                resource.description = (
                    "The server returned HTTP 200 but the response appears to be a "
                    "catch-all/soft-404 page (content-type mismatch or catch-all "
                    "calibration matched), not the actual sensitive file."
                )
                resource.evidence = (
                    f"Soft-404 detected at {url_info.url}: status 200 with "
                    f"content-type {http_response.content_type}"
                )
                return resource

            # Check if directory listing
            if http_response.is_directory_listing:
                resource.resource_type = ResourceType.DIRECTORY_LISTING
                resource.severity = Severity.MEDIUM
                resource.description = "Directory listing is enabled, exposing all files in this directory"
                resource.evidence = f"Directory listing detected at {url_info.url}"

            # Upgrade severity if critical exposure
            if resource_type in [
                ResourceType.SOURCE_CONTROL_EXPOSURE,
                ResourceType.DATABASE_EXPOSURE,
            ] and resource.is_accessible:
                if severity != Severity.CRITICAL:
                    resource.severity = Severity.CRITICAL

        return resource

    # Extensions whose real content is never legitimately served as text/html.
    # A 200 with text/html for these indicates a catch-all/soft-404 page.
    _NON_HTML_EXTENSIONS = {
        ".env", ".ini", ".conf", ".config", ".cfg", ".yml", ".yaml",
        ".json", ".xml", ".sql", ".db", ".sqlite", ".sqlite3", ".dump",
        ".log", ".txt", ".csv", ".bak", ".old", ".orig", ".save", ".swp",
        ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar",
        ".key", ".pem", ".crt", ".cer", ".p12", ".pfx",
        ".py", ".php", ".rb", ".sh", ".bat", ".phar",
        ".lock", ".md",
    }

    def _is_soft_404(
        self,
        url_info: URLInfo,
        http_response: HTTPResponse,
        catch_all_detected: bool,
    ) -> bool:
        """
        Detect whether a 200 response is actually a soft-404 / catch-all page.

        Heuristics, in order:
        1. Content sniffing: if the body clearly looks like an HTML page
           (doctype/<html>/<body>) but the filename implies a non-HTML file,
           it's a catch-all page. Conversely, if the body clearly matches the
           claimed file type (e.g. KEY=value for .env), it is NOT a soft-404.
        2. Filename/content-type mismatch: a non-HTML file extension served as
           text/html.
        3. Site-wide catch-all confirmed by calibration.
        """
        content_type = (http_response.content_type or "").lower()
        is_html_type = "text/html" in content_type
        filename = url_info.path.rsplit("/", 1)[-1].lower()
        ext = url_info.extension
        body = http_response.response_sample or ""

        # Heuristic 1: content sniffing. If we have a body, decide from what
        # the content actually is rather than headers alone.
        if body:
            looks_like_html = self._body_looks_like_html(body)

            # Body is real HTML markup but the file should not be HTML.
            if looks_like_html and self._filename_implies_non_html(filename, ext):
                return True

            # Body confirms the claimed non-HTML content (e.g. a real .env with
            # KEY=value lines). Trust the content over a misleading text/html
            # content-type or a catch-all calibration flag.
            if not looks_like_html and self._body_matches_claimed_file(filename, ext, body):
                return False

        if not is_html_type:
            return False

        # Heuristic 2: filename/content-type mismatch (no usable body).
        if ext in self._NON_HTML_EXTENSIONS:
            return True
        if any(marker in filename for marker in self._NON_HTML_FILENAME_MARKERS):
            return True

        # Heuristic 3: site-wide catch-all confirmed by calibration.
        if catch_all_detected:
            return True

        return False

    @staticmethod
    def _body_looks_like_html(body: str) -> bool:
        """Return True if the body clearly contains HTML markup."""
        head = body[:2000].lower()
        return any(
            tag in head
            for tag in ("<!doctype html", "<html", "<head", "<body", "<title>")
        )

    def _filename_implies_non_html(self, filename: str, ext: str) -> bool:
        """Return True if the filename/extension should not be HTML content."""
        return (
            ext in self._NON_HTML_EXTENSIONS
            or any(m in filename for m in self._NON_HTML_FILENAME_MARKERS)
        )

    @staticmethod
    def _body_matches_claimed_file(filename: str, ext: str, body: str) -> bool:
        """
        Return True if the body content positively matches the claimed file
        type, confirming genuine exposure (not a soft-404).
        """
        sample = body[:2000]

        # .env / ini-style: KEY=value lines
        if filename.startswith(".env") or ext in {".env", ".ini", ".conf", ".cfg"}:
            import re as _re
            return bool(_re.search(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*=", sample))

        # JSON
        if ext == ".json" or filename.endswith(".json"):
            stripped = sample.lstrip()
            return stripped.startswith("{") or stripped.startswith("[")

        # SQL dumps
        if ext == ".sql":
            up = sample.upper()
            return any(k in up for k in ("CREATE TABLE", "INSERT INTO", "DROP TABLE", "DATABASE"))

        # Private keys / certs
        if ext in {".key", ".pem", ".crt", ".cer", ".p12", ".pfx"}:
            return "-----BEGIN" in sample

        # Log files: timestamped lines
        if ext == ".log":
            import re as _re
            return bool(_re.search(r"(?m)^\[?\d{4}-\d{2}-\d{2}", sample))

        return False

    # Filename markers (substring match, lowercased) whose real content is
    # never legitimately served as text/html. Catches multi-part names like
    # ".env.production", "config.php.bak", "wp-config.php.save".
    _NON_HTML_FILENAME_MARKERS = {
        ".env", "config.", "configuration.", "settings.", "web.config",
        "app.config", "application.config", "wp-config", "database.",
        ".git/", ".svn/", ".htpasswd", "id_rsa", "composer.",
    }

    def get_curated_sensitive_paths(self) -> list[str]:
        """
        Get a curated list of common sensitive paths to check.

        Returns:
            List of path strings to check against the target
        """
        return [
            # Configuration
            ".env", ".env.local", ".env.production", ".env.development",
            ".env.backup", ".env.old", ".env.example",
            "config.json", "config.php.bak", "config.py",
            "web.config", "app.config", "application.config",
            "settings.py", "settings.json", "settings.yaml",
            "database.yml", "database.php",

            # Laravel specific
            ".env", ".env.backup", ".env.production", ".env.staging",
            "storage/logs/laravel.log", "storage/logs/laravel-*.log",
            "storage/framework/sessions/", "storage/framework/cache/",
            "storage/framework/views/", "storage/app/public/",
            "bootstrap/cache/", "bootstrap/cache/config.php",
            "bootstrap/cache/services.php", "bootstrap/cache/packages.php",
            "vendor/", "composer.json", "composer.lock", "composer.phar",
            "artisan", "artisan.bat",
            "config/app.php", "config/database.php", "config/mail.php",
            "config/services.php", "config/session.php", "config/cache.php",
            "config/queue.php", "config/filesystems.php",
            "public/storage/", "public/.htaccess",
            "app/Http/Controllers/", "app/Models/",
            "database/migrations/", "database/seeds/", "database/factories/",
            "routes/web.php", "routes/api.php", "routes/console.php",
            "resources/views/", "resources/lang/",
            "tests/", "phpunit.xml", "phpunit.xml.dist",
            "webpack.mix.js", "package.json", "package-lock.json",
            "yarn.lock", "mix-manifest.json",
            "server.php", "index.php.bak",
            "public/index.php.bak", "public/.user.ini",
            "storage/debugbar/", "_debugbar/",
            "telescope/", "horizon/", "nova/",
            "laravel-*.log", "laravel.log",
            "query.log", "error.log",

            # Source control
            ".git/config", ".git/HEAD", ".git/index",
            ".git/logs/HEAD", ".git/packed-refs",
            ".svn/entries", ".svn/wc.db",
            ".hg/", ".hg/store/",

            # Database/backups
            "backup.sql", "backup.zip", "backup.tar.gz",
            "database.sql", "db.sql", "dump.sql",
            "backup.db", "backup.sqlite", "backup.sqlite3",
            "data.zip", "files.zip", "backup.7z",
            "mysqldump.sql", "postgres.dump",

            # Logs
            "error.log", "access.log", "debug.log",
            "apache.log", "nginx.log", "application.log",
            "laravel.log", "symfony.log", "rails.log",
            "production.log", "development.log", "test.log",

            # Development
            ".DS_Store", "Thumbs.db", "desktop.ini",
            "package.json", "composer.json", "Gemfile",
            "package-lock.json", "yarn.lock", "composer.lock",
            "Gemfile.lock", "Pipfile.lock", "poetry.lock",
            ".map$", ".tsbuildinfo$",
            ".idea/", ".vscode/",
            "*.sublime-project", "*.sublime-workspace",

            # Credentials
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            ".pem", ".key", ".crt", ".cer", ".p12", ".pfx",
            ".htpasswd", ".htaccess", ".htusers",
            "passwords.txt", "credentials.json", "secrets.json",
            "api_keys.txt", "tokens.txt",

            # Admin panels
            "admin/", "administrator/", "wp-admin/",
            "phpmyadmin/", "adminer/", "mysql/",
            "console/", "dashboard/", "controlpanel/",
            "cpanel/", "webmail/", "plesk/",
            "admin.php", "administrator.php", "login.php",
            "wp-login.php", "admin/login", "admin/dashboard",

            # Upload directories
            "uploads/", "upload/", "files/", "attachments/",
            "documents/", "docs/", "public/", "media/",
            "images/", "img/", "assets/", "static/",
            "storage/", "tmp/uploads/", "temp/uploads/",

            # Development/staging
            "dev/", "development/", "staging/", "testing/",
            "tmp/", "temp/", "temporary/", "test/",
            "beta/", "alpha/", "demo/", "sandbox/",
            "old/", "backup/", "bak/", "archive/",

            # Common web app paths
            "wp-content/", "wp-includes/", "wp-config.php.bak",
            "wp-config.php.save", "wp-config.php.swp",
            "server-status", "server-info", "phpinfo.php",
            "info.php", "test.php", "phpinfo.php5",
            "install.php", "setup.php", "upgrade.php",

            # API endpoints
            "api/", "api/v1/", "api/v2/", "api/docs",
            "swagger/", "swagger-ui/", "api-docs/",
            "graphql/", "graphiql/", "playground/",

            # CI/CD
            ".github/", ".gitlab-ci.yml", ".travis.yml",
            "Jenkinsfile", "docker-compose.yml", "Dockerfile",
            ".dockerignore", "kubernetes/", "k8s/",

            # Monitoring/Debug
            "debug/", "trace/", "profiler/", "_profiler/",
            "telescope/", "clockwork/", "debugbar/",
            "xdebug/", "xhprof/", "blackfire/",

            # Other
            "robots.txt", "sitemap.xml", "sitemap_index.xml",
            "humans.txt", "security.txt", ".well-known/security.txt",
            ".well-known/", "crossdomain.xml", "clientaccesspolicy.xml",
            "favicon.ico", "apple-touch-icon.png",
            "manifest.json", "browserconfig.xml",
            "CHANGELOG.md", "README.md", "LICENSE",
            "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
        ]

    def analyze_path_exposure(
        self,
        path: str,
        base_url: str,
        http_response: HTTPResponse | None = None,
    ) -> DiscoveredResource | None:
        """
        Analyze a specific path for exposure.

        Args:
            path: Path to check (relative or absolute)
            base_url: Base URL of the target
            http_response: Optional HTTP response

        Returns:
            DiscoveredResource if the path is sensitive, None otherwise
        """
        from urllib.parse import urljoin

        from scanner.discovery import normalize_url

        full_url = urljoin(base_url, path)

        url_info = URLInfo(
            url=full_url,
            normalized_url=normalize_url(full_url),
            discovery_source=DiscoverySource.COMMON_PATHS,
        )

        resource = self.analyze_resource(url_info, http_response)

        # Only return if it's actually sensitive
        if resource.resource_type != ResourceType.PUBLIC_EXPECTED:
            return resource

        return None

