# utils/banner.py
import subprocess
import sys

# ---------- Dependency installer ----------
def install_if_missing(package_name):
    try:
        __import__(package_name)
    except ImportError:
        print(f"{package_name} not found. Installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
            print(f"{package_name} installed successfully!\n")
        except subprocess.CalledProcessError:
            print(f"Failed to install {package_name}. Continuing with fallback...\n")

# Auto-check/install required packages
install_if_missing("pyfiglet")
install_if_missing("colorama")

# ---------- Banner function ----------
def print_banner(name="ProbeRaptor", subtitle="Subdomain Reconnaissance Tool", author="Omkar Sahni", version="v0.1", font="slant"):
    try:
        import pyfiglet
        from colorama import init, Fore, Style
        init(autoreset=True)

        art = pyfiglet.figlet_format(name, font=font)
        print(Fore.GREEN + Style.BRIGHT + art)
        print(Fore.CYAN + subtitle)
        print(Fore.YELLOW + f"Developed by {author} — {version}\n")
        print(Fore.CYAN + "=" * 60 + "\n")

    except Exception:
        # Fallback simple banner if pyfiglet/colorama fails
        RESET = "\033[0m"
        FG_GREEN = "\033[32m"
        FG_CYAN  = "\033[36m"
        FG_YELLOW = "\033[33m"
        print(FG_GREEN + f"=== {name} ===" + RESET)
        print(FG_CYAN + subtitle + RESET)
        print(FG_YELLOW + f"Developed by {author} — {version}\n" + RESET)
        print(FG_CYAN + "=" * 60 + RESET + "\n")

