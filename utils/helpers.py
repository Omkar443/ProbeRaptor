# This is a helper that will print the logo of the tool and velidate the url if it is valid or not

def banner():
        banner = """
                    BugBuntyReconTool
                    ================
        """
        return banner


banner()

def validate_url(domain):
    import re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return re.match(pattern, domain) is not None


