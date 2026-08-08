# WebExpose Scanner

**A simple tool to check your websites for exposed files and sensitive information.**

**Made by:** Christos Ploutarchou  
**Contact:** cploutarchou@gmail.com  
**GitHub:** https://github.com/cploutarchou/webexpose-scanner

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

### Option 1: Using uv (Fastest)

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

### Option 2: Using regular Python

```bash
# Install needed packages
pip install -r requirements.txt

# Run the scanner
python main.py audit https://your-website.com
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

## 📜 License

MIT License - See LICENSE file for details

**Remember:** Only use this on websites you own or have explicit permission to test!

---

## 🙏 Final Words

Thank you for checking out WebExpose Scanner!

This project started as something forgotten on my disk and is now a tool that can help people secure their websites. I hope you find it useful, learn something from it, or maybe even help make it better.

Security matters, and we all do our part when we share knowledge and tools with each other.

---

**Version:** 1.0.0  
**Updated:** 2026  
**Made with ❤️ by Christos Ploutarchou**  
**GitHub:** https://github.com/cploutarchou/webexpose-scanner