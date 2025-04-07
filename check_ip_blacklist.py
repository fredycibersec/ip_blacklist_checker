#!/usr/bin/env python3
"""
IP Blacklist Checker - Enhanced script to check if an IP is listed in common blacklists
with rich formatting for better visual presentation
"""

import sys
import socket
import argparse
import time
import math
from concurrent.futures import ThreadPoolExecutor

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.text import Text
    from rich.style import Style
    from rich.align import Align
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Rich library not available. Install with: pip install rich")
    print("Running with basic formatting...\n")

# Initialize Rich console
console = Console()

def reverse_ip(ip):
    """Reverse the IP address for DNS lookups."""
    return '.'.join(reversed(ip.split('.')))

def check_blacklist(ip, blacklist):
    """
    Check if the IP is listed in a specific blacklist.
    Returns a tuple of (blacklist_name, is_listed)
    """
    reversed_ip = reverse_ip(ip)
    lookup = f"{reversed_ip}.{blacklist}"
    
    try:
        socket.gethostbyname(lookup)
        return (blacklist, True)
    except (socket.gaierror, socket.herror):
        return (blacklist, False)

def main():
    parser = argparse.ArgumentParser(description='Check if an IP address is listed in common blacklists.')
    parser.add_argument('ip', help='The IP address to check')
    args = parser.parse_args()
    
    ip = args.ip
    
    # Validate IP format
    try:
        socket.inet_aton(ip)
    except socket.error:
        print(f"Error: '{ip}' is not a valid IP address.")
        sys.exit(1)
    
    if RICH_AVAILABLE:
        console.print(Panel(f"[bold]Checking IP [cyan]{ip}[/] against common blacklists...", 
                           style="blue", expand=False))
    else:
        print(f"\nChecking IP {ip} against common blacklists...\n")
    
    # List of blacklists organized into categories
    blacklist_categories = {
        "Spam Blacklists": [
            "dnsbl-0.uceprotect.net",
            "dnsbl-1.uceprotect.net",
            "dnsbl-2.uceprotect.net",
            "dnsbl-3.uceprotect.net",
            "rbl.abuse.ro",
            "spam.dnsbl.anonmails.de",
            "ips.backscatterer.org",
            "b.barracudacentral.org",
            "bl.blocklist.de",
            "bsb.empty.us",
            "bsb.spamlookup.net",
            "spamsources.fabel.dk",
            "bl.spamcop.net",
            "zen.spamhaus.org",
            "bl.spameatingmonkey.net",
            "backscatter.spameatingmonkey.net",
            "dyna.spamrats.com",
            "noptr.spamrats.com",
            "spam.spamrats.com",
            "bl.mailspike.net",
            "z.mailspike.net",
            "spamguard.leadmon.net",
            "rbl.interserver.net",
            "rbl.schulte.org",
            "cbl.abuseat.org",
            "dnsbl.spfbl.net",
            "bl.suomispam.net",
        ],
        "Security/Malware Blacklists": [
            "dnsbl.dronebl.org",
            "phishing.rbl.msrbl.net",
            "spam.rbl.msrbl.net",
            "dnsbl.kempt.net",
            "mail-abuse.blacklist.jippg.org",
            "wormrbl.imp.ch",
            "spamrbl.imp.ch",
            "dnsrbl.swinog.ch",
            "truncate.gbudb.net",
            "db.wpbl.info",
            "dnsbl.zapbl.net",
            "rhsbl.zapbl.net",
            "rbl2.triumf.ca",
            "blacklist.woody.ch",
        ],
        "Tor/Proxy Blacklists": [
            "torexit.dan.me.uk",
            "exitnodes.tor.dnsbl.sectoor.de",
            "ix.dnsbl.manitu.net",
        ],
        "SORBS Blacklists": [
            "spam.dnsbl.sorbs.net",
            "aspews.ext.sorbs.net",
            "l1.bbfh.ext.sorbs.net",
            "l2.bbfh.ext.sorbs.net",
            "l3.bbfh.ext.sorbs.net",
            "l4.bbfh.ext.sorbs.net",
            "dnsbl.sorbs.net",
            "http.dnsbl.sorbs.net",
            "misc.dnsbl.sorbs.net",
            "smtp.dnsbl.sorbs.net",
            "socks.dnsbl.sorbs.net",
            "zombie.dnsbl.sorbs.net",
            "dul.dnsbl.sorbs.net",
            "block.dnsbl.sorbs.net",
        ],
        "Policy/Bogon Blacklists": [
            "bogons.cymru.com",
            "all.rbl.jp",
            "psbl.surriel.com",
            "cbl.anti-spam.org.cn",
            "cdl.anti-spam.org.cn",
            "bl.drmx.org",
            "bl.konstant.no",
            "orvedb.aupads.org",
            "rsbl.aupads.org",
            "dnsbl.calivent.com.pe",
            "hil.habeas.com",
            "dnsbl.inps.de",
            "relays.nether.net",
            "unsure.nether.net",
        ],
    }
    
    # Flatten the blacklists for checking
    blacklists = []
    for category, services in blacklist_categories.items():
        blacklists.extend(services)
    
    start_time = time.time()
    
    # Use ThreadPoolExecutor to check blacklists concurrently
    listed_count = 0
    
    if RICH_AVAILABLE:
        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Checking blacklists...", total=len(blacklists))
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                for i, blacklist in enumerate(blacklists):
                    result = executor.submit(check_blacklist, ip, blacklist)
                    blacklist_name, is_listed = result.result()
                    results.append((blacklist_name, is_listed))
                    progress.update(task, advance=1)
    else:
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(lambda bl: check_blacklist(ip, bl), blacklists))
    
    # Calculate trust score using progressive penalty
    for _, is_listed in results:
        if is_listed:
            listed_count += 1
    
    # Progressive penalty trust score calculation
    # Each blacklist hit reduces the score with increasing penalty
    # First hit: -5 points, Second hit: -10 points, Third hit: -15 points, etc.
    trust_score = 100
    for i in range(1, listed_count + 1):
        penalty = i * 5
        trust_score -= penalty
    trust_score = max(0, trust_score)  # Ensure score doesn't go below 0
    
    # Determine trust assessment
    if trust_score >= 90:
        trust_assessment = "Highly Trusted: This IP shows no significant signs of malicious activity"
        trust_color = "green"
    elif trust_score >= 75:
        trust_assessment = "Trusted: This IP has minimal presence on blacklists"
        trust_color = "green"
    elif trust_score >= 50:
        trust_assessment = "Moderately Trusted: This IP appears on some blacklists but is generally acceptable"
        trust_color = "yellow"
    elif trust_score >= 25:
        trust_assessment = "Suspicious: This IP appears on several blacklists and should be treated with caution"
        trust_color = "orange"
    else:
        trust_assessment = "Untrusted: This IP appears on many blacklists and is likely engaged in malicious activity"
        trust_color = "red"
    
    # Print results
    if RICH_AVAILABLE:
        # Organize results by category
        categorized_results = {}
        
        # Map blacklist results to their categories
        for blacklist, is_listed in results:
            for category, services in blacklist_categories.items():
                if blacklist in services:
                    if category not in categorized_results:
                        categorized_results[category] = []
                    categorized_results[category].append((blacklist, is_listed))
        
        # Print results by category
        for category, category_results in categorized_results.items():
            # Create table for each category
            table = Table(show_header=True, header_style="bold", box=box.ROUNDED)
            table.add_column(f"{category} ({len(category_results)})", style="cyan", no_wrap=True)
            table.add_column("Status", style="magenta")
            
            # Track listed count per category
            category_listed = 0
            
            for blacklist, is_listed in category_results:
                if is_listed:
                    category_listed += 1
                status_text = Text("LISTED", style="bold red") if is_listed else Text("NOT LISTED", style="bold green")
                table.add_row(blacklist, status_text)
            
            # Add category summary to table caption
            table.caption = f"Listed on {category_listed} out of {len(category_results)} blacklists in this category"
            
            console.print(table)
        # Create trust score visualization
        bar_width = 50
        filled_bars = int(trust_score / 100 * bar_width)
        empty_bars = bar_width - filled_bars
        
        # Create trust score panel
        trust_panel = Panel(
            f"[{trust_color}]{'█' * filled_bars}{'░' * empty_bars}[/] {trust_score:.0f}%\n\n"
            f"[bold {trust_color}]{trust_assessment}[/]",
            title="[bold]Trust Score Assessment[/]",
            border_style=trust_color,
            box=box.ROUNDED
        )
        console.print(trust_panel)
        
        # Create summary panel
        summary = f"[bold]IP:[/] [cyan]{ip}[/]\n"
        summary += f"[bold]Listed on:[/] [red]{listed_count}[/] out of [cyan]{len(blacklists)}[/] blacklists\n"
        
        # Add category breakdown to summary
        summary += f"\n[bold]Category Breakdown:[/]\n"
        for category, category_results in categorized_results.items():
            category_listed = sum(1 for _, is_listed in category_results if is_listed)
            if category_listed > 0:
                summary += f"- {category}: [red]{category_listed}[/] out of {len(category_results)}\n"
            else:
                summary += f"- {category}: [green]0[/] out of {len(category_results)}\n"
        
        summary += f"\n[bold]Check completed in:[/] [cyan]{time.time() - start_time:.2f}[/] seconds"
        console.print(Panel(summary, title="[bold]Summary[/]", border_style="blue", box=box.ROUNDED))
        
    else:
        # Basic formatting if Rich is not available
        # Organize results by category
        categorized_results = {}
        
        # Map blacklist results to their categories
        for blacklist, is_listed in results:
            for category, services in blacklist_categories.items():
                if blacklist in services:
                    if category not in categorized_results:
                        categorized_results[category] = []
                    categorized_results[category].append((blacklist, is_listed))
        
        # Print results by category
        for category, category_results in categorized_results.items():
            category_listed = sum(1 for _, is_listed in category_results if is_listed)
            print(f"\n{category} ({len(category_results)} services, {category_listed} listings):")
            print("-" * 60)
            print(f"{'Blacklist':<40} {'Status':<15}")
            print("-" * 55)
            
            for blacklist, is_listed in category_results:
                status = "LISTED" if is_listed else "NOT LISTED"
                print(f"{blacklist:<40} {status:<15}")
        
        print("\nTrust Score Assessment:")
        print(f"Score: {trust_score:.0f}%")
        print(f"Assessment: {trust_assessment}")
        
        print("\nSummary:")
        print(f"IP: {ip}")
        print(f"Listed on {listed_count} out of {len(blacklists)} blacklists")
        
        # Add category breakdown to summary
        print("\nCategory Breakdown:")
        for category, category_results in categorized_results.items():
            category_listed = sum(1 for _, is_listed in category_results if is_listed)
            print(f"- {category}: {category_listed} out of {len(category_results)}")
            
        print(f"\nCheck completed in {time.time() - start_time:.2f} seconds\n")

if __name__ == "__main__":
    main()
