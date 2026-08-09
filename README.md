# WebExpose Scanner

---

## ⚠️ Important - Read This First

**This tool is ONLY for websites you own or have permission to test.**

Using this tool on websites you don't own is against the law. The people who made this tool are not responsible if someone uses it the wrong way.

---

## 📖 The Story Behind This Project

### How This Project Came to Life

I found this project sitting on my disk - it was something I had worked on a while back and saved away. Recently, due to some events that made me think more about security, I decided to take another look at it.

When I opened it up, I realized it still had some good ideas, but it needed work to run on today's Python. So I spent time updating it to use the newest Python version and modern tools.

**Why share it now?**

I believe that old projects shouldn't just sit on disks gathering dust. Sometimes the best tools come from projects that people forgot about or set aside. By updating this and sharing it, I want to show that:

- Old projects can be made new again
- Good ideas don't expire
- The security community can benefit from revived projects
- Everyone deserves access to decent security tools

### What This Tool Does

This tool helps you find problems on your website like:

- **Files that shouldn't be public** - Documents, backups, configuration files
- **Secret information** - Passwords, API keys, tokens
- **Security issues** - Directory listings, exposed data
- **Old files** - Things that are still online but shouldn't be

It does this by:
- Looking at your website pages (like a search engine)
- Checking common places where sensitive files might be
- Testing for exposed directories
- Looking for patterns that look like secrets

### 🎯 CMS & Framework Support

WebExpose Scanner has **comprehensive detection** for the most popular CMSs and frameworks:

#### **WordPress** (Most Popular CMS)
- ✅ `wp-config.php` and all backup variants (.bak, .save, .swp, .old, .orig, ~, #, .txt, .zip, .tar.gz, etc.)
- ✅ `wp-content/uploads/` (exposed uploads)
- ✅ `wp-content/debug.log` and `error.log`
- ✅ `wp-admin/` and `wp-includes/` directories
- ✅ `wp-login.php`, `xmlrpc.php` (common attack vectors)
- ✅ `wp-json/` (REST API exposure)
- ✅ Plugin and theme directories
- ✅ All wp-config.php backup variants (0-9, a-z)

#### **Laravel** (PHP Framework)
- ✅ `.env` files (all variants: .local, .production, .staging, .testing, .example, .backup, .old)
- ✅ `storage/logs/laravel.log` and all log files
- ✅ `storage/framework/` (sessions, cache, views)
- ✅ `bootstrap/cache/` (config, services, packages, routes, events)
- ✅ `config/` directory (app, database, mail, services, session, cache, queue, filesystems, auth, etc.)
- ✅ `routes/` directory (web, api, console, channels)
- ✅ `composer.json`, `composer.lock`, `vendor/` directory
- ✅ `artisan` command
- ✅ `public/storage/`, `public/.htaccess`
- ✅ `app/` directory (Controllers, Models, Providers, etc.)
- ✅ `database/` directory (migrations, seeds, factories)
- ✅ `resources/` directory (views, lang, js, css, sass)
- ✅ `tests/` directory, `phpunit.xml`
- ✅ `webpack.mix.js`, `mix-manifest.json`, `package.json`
- ✅ Debug tools: Telescope, Horizon, Nova, Debugbar
- ✅ Laravel Sail, Vapor, Forge, Envoyer, Herd, Valet, Homestead
- ✅ Laravel Octane, Sanctum, Passport, Scout, Socialite, Cashier
- ✅ Laravel Dusk, Pint, Breeze, Jetstream, Fortify, Spark
- ✅ Laravel Livewire, Inertia, Filament, Backpack, Voyager
- ✅ OAuth keys (`oauth-private.key`, `oauth-public.key`)
- ✅ Docker files (`docker-compose.yml`, `Dockerfile`)

#### **Django** (Python Framework)
- ✅ `settings.py` (all variants: base, local, production, development, staging, test)
- ✅ `local_settings.py`, `settings_local.py`
- ✅ `.env` files
- ✅ `requirements.txt`, `Pipfile`, `pyproject.toml`, `poetry.lock`
- ✅ `manage.py`, `wsgi.py`, `asgi.py`, `urls.py`
- ✅ `db.sqlite3` (database file)
- ✅ `__pycache__/`, `.pyc`, `.pyo` files
- ✅ `migrations/` directory
- ✅ `static/`, `staticfiles/`, `media/`, `templates/` directories
- ✅ Celery files, coverage files, test files
- ✅ `gunicorn.conf.py`, `uwsgi.ini`, `supervisor.conf`

#### **Drupal** (Enterprise CMS)
- ✅ `sites/default/settings.php` (all backup variants)
- ✅ `sites/default/files/` (all subdirectories: private, backup, tmp, config, styles, js, css, php, xmlsitemap, languages, translations)
- ✅ `sites/all/modules/`, `themes/`, `libraries/`, `drush/`
- ✅ `core/`, `vendor/` directories
- ✅ `update.php`, `install.php`, `cron.php`, `xmlrpc.php`, `authorize.php`, `rebuild.php`
- ✅ All `.well-known/` paths
- ✅ `composer.json`, `composer.lock`

#### **Joomla** (Popular CMS)
- ✅ `configuration.php` (all backup variants: .bak, .old, .save, .swp, ~, .dist, .txt, .zip, .tar.gz)
- ✅ `administrator/` directory (all subdirectories: components, modules, templates, language, manifests, logs, cache, tmp)
- ✅ `components/`, `modules/`, `plugins/`, `templates/`, `language/`, `libraries/`, `media/`, `images/`, `includes/`, `cli/`, `bin/`
- ✅ `cache/`, `tmp/`, `logs/` directories
- ✅ All documentation files (CHANGELOG, README, LICENSE, etc.)
- ✅ All CI/CD and config files

#### **General Detection**
- ✅ Source control: `.git/`, `.svn/`, `.hg/`
- ✅ Database files: `.sql`, `.sqlite`, `.db`, `.dump`
- ✅ Backup files: `.bak`, `.backup`, `.old`, `.orig`, `.save`, `.tmp`
- ✅ Archive files: `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.gz`, `.7z`, `.rar`
- ✅ Log files: `.log`, `.trace`, `.out`, `.err`
- ✅ Credentials: `id_rsa`, `.pem`, `.key`, `.crt`, `.htpasswd`, `passwords.txt`, `credentials.json`
- ✅ Development files: `.DS_Store`, `Thumbs.db`, `package-lock.json`, `yarn.lock`
- ✅ CI/CD: `.github/`, `.gitlab-ci.yml`, `Jenkinsfile`, `docker-compose.yml`, `Dockerfile`
- ✅ Debug tools: `debug/`, `profiler/`, `xdebug/`, `blackfire/`

### 📊 Detection Statistics

| CMS/Framework | Patterns | Severity | Coverage |
|---------------|----------|----------|----------|
| **WordPress** | 60+      | HIGH     | ✅ Complete |
| **Laravel**   | 200+     | HIGH     | ✅ Complete |
| **Django**    | 50+      | HIGH     | ✅ Complete |
| **Drupal**    | 80+      | HIGH     | ✅ Complete |
| **Joomla**    | 100+     | HIGH     | ✅ Complete |
| **General**   | 50+      | Various  | ✅ Complete |
| **TOTAL**     | **540+** | -        | **✅ Comprehensive** |

### What This Tool Does NOT Do

It does NOT:
- Try to break into websites
- Bypass login systems
- Delete or change anything
- Attack websites in any way

This is a **passive tool** - it only looks at what's already publicly available.

---

## 🤝 Community & Contributions

### Why I'm Sharing This

I'm putting this out there because:

- **Security tools should be available to everyone**
- **Other developers might find it useful**
- **Penetration testers need good tools**
- **Learning happens when people share**

### Welcome Features & Ideas

If you have ideas for making this tool better, I'd love to hear them! Some things I'm particularly interested in:

- **New ways to find exposed files**
- **Better secret detection**
- **Faster scanning methods**
- **New report formats**
- **Bug fixes and improvements**
- **Documentation help**

### How to Contribute

Even if you're new to this kind of work, your ideas matter! You can help by:

- **Reporting bugs** - Tell me when something doesn't work
- **Suggesting features** - What would make this more useful?
- **Improving documentation** - Help make things clearer
- **Sharing ideas** - What security problems should this check for?
- **Code contributions** - If you know Python, feel free to make pull requests

### Support

If you need help or want to chat:
- **Open an issue** on GitHub
- **Email me** at cploutarchou@gmail.com
- **Share your ideas** for improvements

I can't promise I'll have all the answers, but I'll do my best to help and learn together.

---

## 🚀 How to Install

### Option 1: From PyPI (Easiest) ⭐

**Install from PyPI** - This is the easiest way to get started!

```bash
# Install the scanner
pip install webexpose-scanner

# You're done! Now you can use it anywhere:
webexpose audit https://your-website.com
```

That's it! No need to clone the repository or install dependencies manually.

**PyPI Repository:** https://pypi.org/project/webexpose-scanner/

### Option 2: Using uv (Fastest for Development)

```bash
# Install uv (if you don't have it)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Get the code
git clone https://github.com/cploutarchou/webexpose-scanner.git
cd webexpose-scanner

# Install needed packages
uv sync

# Run the scanner
uv run main.py audit https://your-website.com
```

### Option 3: Using regular Python (Traditional)

```bash
# Get the code
git clone https://github.com/cploutarchou/webexpose-scanner.git
cd webexpose-scanner

# Install needed packages
pip install -r requirements.txt

# Run the scanner
python main.py audit https://your-website.com
```

---

## ⚡ Quick Start (For PyPI Users)

Just installed from PyPI? Here's how to get started in 30 seconds:

```bash
# Run your first scan
webexpose audit https://your-website.com

# The scan will:
# 1. Discover URLs from robots.txt, sitemap.xml, and links
# 2. Crawl your website (up to 100 pages by default)
# 3. Check common sensitive file paths
# 4. Look for exposed secrets
# 5. Generate detailed reports

# Check the reports
cat reports/your-website.com/report.md
```

**That's it!** Your security report is ready in the `reports/` folder.

### First Time Scanning Tips

```bash
# Start with a smaller scan (good for testing)
webexpose audit https://your-website.com --max-pages 50

# Only check for sensitive files (no crawling)
webexpose audit https://your-website.com --passive-only

# See detailed output
webexpose audit https://your-website.com --verbose
```

---

## 📖 How to Use

### Basic Usage

```bash
# Scan your website
python main.py audit https://your-website.com

# Put reports in a different folder
python main.py audit https://your-website.com --output ./my-reports

# Check more pages
python main.py audit https://your-website.com --max-pages 200
```

### Advanced Options

```bash
# Only check sensitive paths (no crawling)
python main.py audit https://your-website.com --passive-only

# Include subdomains
python main.py audit https://your-website.com --include-subdomains

# Go faster (more workers)
python main.py audit https://your-website.com --workers 10

# Go slower between requests
python main.py audit https://your-website.com --rate-limit 1.0

# See what's happening
python main.py audit https://your-website.com --verbose
```

### Control What Reports You Get

```bash
# Only JSON report
python main.py audit https://your-website.com --no-markdown --json

# All types of reports
python main.py audit https://your-website.com --markdown --json --text

# Your own report folder
python main.py audit https://your-website.com --output /path/to/reports
```

---

## 📊 What the Reports Tell You

When the scan finishes, you'll get:

### Screen Output
Shows you quick results like:
- How many pages were checked
- What files were found
- Any important issues found
- Where the reports were saved

### Markdown Report (`report.md`)
A detailed report with:
- What was found
- How bad each problem is
- What you should do to fix it
- Evidence of each problem

### JSON Report (`report.json`)
Computer-readable data that you can:
- Use in other tools
- Keep track of changes over time
- Make your own custom reports

---

## 🎯 Understanding the Results

### Severity Levels

**[!] CRITICAL** - Fix this right now!
- Someone can steal your secrets
- Database backups are exposed
- Private keys are visible

**[*] HIGH** - Fix this soon
- Configuration files exposed
- Source code visible
- Backup files accessible

**[+] MEDIUM** - Fix this when you can
- Internal documents visible
- Log files exposed
- Some data files accessible

**[i] LOW** - Nice to fix
- Old files still online
- Development artifacts visible

**[.] INFO** - Just information
- Regular public files
- Normal website content

---

## 🔍 What Gets Checked

### File Types
- **Documents**: PDF, Word, Excel, PowerPoint
- **Data**: JSON, XML, YAML, CSV
- **Backups**: ZIP, TAR, SQL, BAK files
- **Configs**: .env, config files, .git folders
- **Logs**: Error logs, access logs
- **Keys**: Private keys, certificates

### Common Problems Found
- .env files with database passwords
- .git/config files exposed
- backup.sql files visible
- .env.backup files
- Directory listings enabled
- Old development files

---

## 🛡️ How It Keeps You Safe

### Scope Protection
- Only checks the website you tell it to
- Blocks checking private IP addresses
- Prevents redirect attacks
- Stops if it tries to leave your website

### Respectful Scanning
- Goes slowly between requests (default: 0.3 seconds)
- Doesn't download huge files
- Times out if a page takes too long
- Can limit how many pages to check

### Safe Reporting
- Hides actual secrets found (only shows ***)
- Never shows full passwords or keys
- Just enough info to fix the problems

---

## 📈 Example Results

```
================================================================================
                              SCAN SUMMARY
================================================================================

Target:                     https://your-website.com
Scan Duration:              45.2 seconds

URLs discovered:            412
URLs checked:               287
Currently accessible:       43

Documents:                   21
Images:                      11
Data files:                  4
Potential sensitive files:   3

================================================================================
                           SECURITY FINDINGS
================================================================================

[!] critical            0
[*] high                2
[+] medium              5
[i] low                 9
[.] info               27

Secrets detected:            7
```

---

## 🔧 What to Do After Scanning

1. **Look at the reports** - Check the report.md file
2. **Fix the big problems first** - Start with [!] and [*] items
3. **Change any exposed secrets** - Rotate passwords, API keys
4. **Remove exposed files** - Delete or protect sensitive files
5. **Check again later** - Run the scan periodically

---

## 📋 Requirements

- Python 3.12 or newer
- Internet connection
- Permission to test the target website

---

## ❓ Common Questions

**Q: Is this tool legal to use?**  
A: Yes, if you only test websites you own or have written permission to test.

**Q: Will this slow down my website?**  
A: It's designed to be very gentle - it waits between requests and doesn't overload servers.

**Q: What if I find something bad?**  
A: Fix it right away if it's critical or high severity. The report tells you how to fix each problem.

**Q: Can I help improve this tool?**  
A: Absolutely! I welcome new features, bug fixes, ideas, and support from anyone interested.

**Q: Do I need to be a programmer to use this?**  
A: Not really! If you can run basic commands, you can use this tool.

**Q: How did you update this old project?**  
A: I updated the code to work with modern Python, improved the security features, and made it easier to use. It's a great example of how old projects can be made useful again.

---

## 🆘 Getting Help

If you have problems:
- Check that Python 3.12+ is installed
- Make sure all dependencies are installed
- Verify you have permission to test the target
- Try with `--verbose` flag to see more details
- Ask for help on GitHub issues

**Report bugs or ask questions:**  
https://github.com/cploutarchou/webexpose-scanner/issues

---

## 🔗 Resources

### Official Links

- **PyPI Package:** https://pypi.org/project/webexpose-scanner/
- **GitHub Repository:** https://github.com/cploutarchou/webexpose-scanner
- **Issue Tracker:** https://github.com/cploutarchou/webexpose-scanner/issues
- **Email Support:** cploutarchou@gmail.com

### Installation Methods

| Method | Command | Best For |
|--------|---------|----------|
| **PyPI** | `pip install webexpose-scanner` | Everyone - easiest way |
| **uv** | `uv sync` (in repo) | Development, faster |
| **pip** | `pip install -r requirements.txt` | Traditional setup |
| **Git Clone** | `git clone + pip install` | Contributing, source code |

### Requirements

- **Python 3.12 or newer**
- **Internet connection**
- **Permission to test target website**

---

## 📜 License

MIT License - See LICENSE file for details

**Remember:** Only use this on websites you own or have explicit permission to test!

---

## 🙏 Final Words

Thank you for checking out WebExpose Scanner!

This project started as something forgotten on my disk and is now a tool that can help people secure their websites. I hope you find it useful, learn something from it, or maybe even help make it better.

Security matters, and we all do our part when we share knowledge and tools with each other.

---
