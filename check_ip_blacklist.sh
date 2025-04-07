#!/bin/bash

# check_ip_blacklist.sh - Check an IP address against multiple blacklist services
# Usage: ./check_ip_blacklist.sh <ip_address>
#
# This script checks an IP address against common blacklist services and
# generates a report showing whether the IP is listed in each blacklist.
# It also includes basic WHOIS information about the IP.

# ANSI color codes
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
BOLD="\033[1m"
RESET="\033[0m"

# Gradient colors for trust score bar
COLOR_RED="\033[38;5;196m"
COLOR_ORANGE="\033[38;5;202m"
COLOR_YELLOW="\033[38;5;226m"
COLOR_YELLOWGREEN="\033[38;5;190m"
COLOR_GREEN="\033[38;5;46m"

# Unicode symbols
CHECK_MARK="✓"
X_MARK="✗"
RIGHT_ARROW="►"

# Function to reverse an IP address (for DNS-based blacklist queries)
reverse_ip() {
    local ip="$1"
    echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}'
}

# Function to check if an IP is in a blacklist
check_blacklist() {
    local reversed_ip="$1"
    local blacklist="$2"
    local blacklist_name="$3"
    
    printf "${BOLD}${BLUE}  %-40s" "$blacklist_name"
    
    result=$(host -W 2 "$reversed_ip.$blacklist" 2>&1)
    
    if [[ $result == *"has address"* || $result == *"domain name pointer"* ]]; then
        printf " ${RED}${X_MARK} LISTED${RESET}\n"
        return 1
    else
        printf " ${GREEN}${CHECK_MARK} NOT LISTED${RESET}\n"
        return 0
    fi
}

# Function to get WHOIS information
get_whois_info() {
    local ip="$1"
    whois "$ip" | grep -E "Organization|Country|City|State|Address|NetRange|CIDR|OrgName|NetName" | head -15
}

# Function to print fancy timestamp
print_timestamp() {
    printf "${CYAN}%s ${MAGENTA}at ${CYAN}%s${RESET}" "$(date "+%A, %B %d, %Y")" "$(date "+%H:%M:%S %Z")"
}

# Main script starts here

# Check if an IP address was provided
if [ $# -ne 1 ]; then
    echo -e "${RED}Error: Missing IP address${RESET}"
    echo "Usage: $0 <ip_address>"
    exit 1
fi

IP="$1"

# Validate IP address format
if ! [[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${RED}Error: Invalid IP address format${RESET}"
    echo "Please provide a valid IPv4 address (e.g., 192.168.1.1)"
    exit 1
fi

# Reverse the IP address for blacklist checking
REVERSED_IP=$(reverse_ip "$IP")

# Print ASCII art header
cat << EOF
$(echo -e "${BLUE}")
 ▄▄▄▄    ██▓    ▄▄▄       ▄████▄   ██ ▄█▀ ██▓     ██▓  ██████ ▄▄▄█████▓
▓█████▄ ▓██▒   ▒████▄    ▒██▀ ▀█   ██▄█▒ ▓██▒    ▓██▒▒██    ▒ ▓  ██▒ ▓▒
▒██▒ ▄██▒██░   ▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒██░    ▒██▒░ ▓██▄   ▒ ▓██░ ▒░
▒██░█▀  ▒██░   ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒██░    ░██░  ▒   ██▒░ ▓██▓ ░ 
░▓█  ▀█▓░██████▒▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░██████▒░██░▒██████▒▒  ▒██▒ ░ 
░▒▓███▀▒░ ▒░▓  ░▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░ ▒░▓  ░░▓  ▒ ▒▓▒ ▒ ░  ▒ ░░   
▒░▒   ░ ░ ░ ▒  ░ ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░░ ░ ▒  ░ ▒ ░░ ░▒  ░ ░    ░    
 ░    ░   ░ ░    ░   ▒   ░        ░ ░░ ░   ░ ░    ▒ ░░  ░  ░    ░      
 ░          ░  ░     ░  ░░ ░      ░  ░       ░  ░ ░        ░           
      ░                  ░                                              
$(echo -e "${RESET}")
EOF

# Print header
BOX_WIDTH=71  # Define a consistent box width
echo -e "\n${BOLD}${BLUE}${BOLD} IP BLACKLIST CHECK REPORT ${RESET}"
echo ""
printf "  ${BOLD}IP Address:${RESET} ${YELLOW}%s${RESET}\n" "$IP"
printf "  ${BOLD}Date:${RESET} "
printf "${CYAN}%s ${MAGENTA}at ${CYAN}%s${RESET}\n" "$(date "+%A, %B %d, %Y")" "$(date "+%H:%M:%S %Z")"
echo -e "\n"

# Print WHOIS information
echo -e "${BOLD}${BLUE}${BOLD} WHOIS INFORMATION ${RESET}"
echo ""
get_whois_info "$IP" | while read line; do
    printf "  ${YELLOW}%s${RESET}\n" "$line"
done
echo ""

# Print blacklist check header
echo -e "\n\n${BOLD}${BLUE}${BOLD} BLACKLIST CHECKS ${RESET}"
echo ""
printf "  ${BOLD}%-40s${RESET} ${BOLD}%s${RESET}\n" "Blacklist Service" "Result"

# Counter for listed blacklists
LISTED_COUNT=0
TOTAL_COUNT=0

# Check against various blacklists
blacklists=(
    # PRIMARY SERVICES: Confirmed to detect 127.0.0.2 as blacklisted
    # These services are proven to work with test IPs and reliably detect known blacklisted addresses
    "dnsbl-0.uceprotect.net:UCEPROTECT Level 0"
    "dnsbl-1.uceprotect.net:UCEPROTECT Level 1"
    "dnsbl-2.uceprotect.net:UCEPROTECT Level 2"
    "dnsbl-3.uceprotect.net:UCEPROTECT Level 3"
    "rbl.abuse.ro:Abuse.ro RBL"
    "spam.dnsbl.anonmails.de:ANONMAILS"
    "ips.backscatterer.org:Backscatterer"
    "b.barracudacentral.org:Barracuda"
    "bl.blocklist.de:Blocklist.de"
    "bsb.empty.us:Empty.us BSB"
    "bsb.spamlookup.net:Spamlookup BSB"
    "cbl.abuseat.org:Abuseat CBL"
    "bogons.cymru.com:Cymru Bogons"
    "torexit.dan.me.uk:TOR Exit Nodes"
    "dnsbl.dronebl.org:DroneBL"
    "spamsources.fabel.dk:Fabel Spamsources"
    "rbl.interserver.net:InterServer RBL"
    "mail-abuse.blacklist.jippg.org:JIPPG Blacklist"
    "dnsbl.kempt.net:Kempt DNSBL"
    "spamguard.leadmon.net:Leadmon SpamGuard"
    "z.mailspike.net:MailSpike Z"
    "bl.mailspike.net:MailSpike"
    "psbl.surriel.com:Surriel PSBL"
    "dyna.spamrats.com:SpamRats Dyna"
    "noptr.spamrats.com:SpamRats NoPTR"
    "spam.spamrats.com:SpamRats Spam"
    "rbl.schulte.org:Schulte RBL"
    "backscatter.spameatingmonkey.net:SpamEatingMonkey Backscatter"
    "bl.spameatingmonkey.net:SpamEatingMonkey Blacklist"
    "bl.spamcop.net:SpamCop"
    "zen.spamhaus.org:Spamhaus ZEN"
    "bl.suomispam.net:Suomispam"
    "dnsrbl.swinog.ch:Swinog"
    "truncate.gbudb.net:GBUDB"
    "db.wpbl.info:WPBL"
    "dnsbl.zapbl.net:ZAPBL DNSBL"
    "dnsbl.spfbl.net:SPFBL"
    
    # SECONDARY SERVICES: Reachable but didn't detect 127.0.0.2 as blacklisted
    # These services are functioning and might detect other IPs or become more responsive in the future
    "spam.dnsbl.sorbs.net:SORBS Spam"
    "aspews.ext.sorbs.net:SORBS ASPEWS"
    "l1.bbfh.ext.sorbs.net:SORBS BBFH L1"
    "l2.bbfh.ext.sorbs.net:SORBS BBFH L2"
    "l3.bbfh.ext.sorbs.net:SORBS BBFH L3"
    "l4.bbfh.ext.sorbs.net:SORBS BBFH L4"
    "dnsbl.calivent.com.pe:Calivent DNSBL"
    "cbl.anti-spam.org.cn:Anti-Spam.org.cn CBL"
    "cdl.anti-spam.org.cn:Anti-Spam.org.cn CDL"
    "bl.drmx.org:DRMX Blacklist"
    "spamrbl.imp.ch:IMP SpamRBL"
    "wormrbl.imp.ch:IMP WormRBL"
    "hil.habeas.com:Habeas HIL"
    "dnsbl.inps.de:INPS DNSBL"
    "bl.konstant.no:Konstant Blacklist"
    "phishing.rbl.msrbl.net:MSRBL Phishing"
    "spam.rbl.msrbl.net:MSRBL Spam"
    "relays.nether.net:Nether.net Relays"
    "unsure.nether.net:Nether.net Unsure"
    "ix.dnsbl.manitu.net:Manitu IX"
    "orvedb.aupads.org:AUPADS ORVEDB"
    "all.rbl.jp:RBL.jp"
    "rsbl.aupads.org:AUPADS RSBL"
    "exitnodes.tor.dnsbl.sectoor.de:Sectoor TOR Exit Nodes"
    "dnsbl.sorbs.net:SORBS"
    "http.dnsbl.sorbs.net:SORBS HTTP"
    "misc.dnsbl.sorbs.net:SORBS Misc"
    "smtp.dnsbl.sorbs.net:SORBS SMTP"
    "socks.dnsbl.sorbs.net:SORBS SOCKS"
    "zombie.dnsbl.sorbs.net:SORBS Zombie"
    "dul.dnsbl.sorbs.net:SORBS DUL"
    "block.dnsbl.sorbs.net:SORBS Block"
    "rbl2.triumf.ca:Triumf RBL2"
    "blacklist.woody.ch:Woody Blacklist"
    "rhsbl.zapbl.net:ZAPBL RHSBL"
)

# Check each blacklist
for blacklist_entry in "${blacklists[@]}"; do
    IFS=':' read -r blacklist_domain blacklist_name <<< "$blacklist_entry"
    
    check_blacklist "$REVERSED_IP" "$blacklist_domain" "$blacklist_name"
    if [ $? -eq 1 ]; then
        ((LISTED_COUNT++))
    fi
    ((TOTAL_COUNT++))
done
echo ""

# Print summary
echo -e "\n\n${BOLD}${BLUE}${BOLD} SUMMARY ${RESET}"
echo ""
if [ $LISTED_COUNT -eq 0 ]; then
    printf "  ${GREEN}${BOLD}The IP address %s is not listed in any of the checked blacklists.${RESET}\n" "$IP"
else
    LISTED_MSG="The IP address $IP is listed in $LISTED_COUNT out of $TOTAL_COUNT blacklists."
    printf "  ${RED}${BOLD}%s${RESET}\n" "$LISTED_MSG"
fi
echo ""

# Calculate trust score and display trust section
echo -e "\n\n${BOLD}${BLUE}${BOLD} TRUST IP SECTION ${RESET}"
echo ""

# Calculate trust score using a progressive penalty system
# Each blacklist hit reduces the score by a progressive amount
# First hit: -5 points, Second hit: -10 points, Third hit: -15 points, etc.
TRUST_SCORE=$(awk "BEGIN {
    score = 100;
    for (i = 1; i <= $LISTED_COUNT; i++) {
        penalty = i * 5;
        score -= penalty;
    }
    if (score < 0) score = 0;
    print score
}")
# Convert to integer using awk to avoid locale-specific issues with printf
TRUST_SCORE_INT=$(awk "BEGIN {printf \"%.0f\", $TRUST_SCORE}")
# Create visual bar representation with Unicode block characters (50 chars total)
BAR_WIDTH=50
FILLED_WIDTH=$(awk "BEGIN {print int(${TRUST_SCORE_INT} * ${BAR_WIDTH} / 100)}")
EMPTY_WIDTH=$(awk "BEGIN {print ${BAR_WIDTH} - ${FILLED_WIDTH}}")

# Create the gradient colored bar based on trust score
if [ $TRUST_SCORE_INT -ge 90 ]; then
    BAR_COLOR="${COLOR_GREEN}"
elif [ $TRUST_SCORE_INT -ge 75 ]; then
    BAR_COLOR="${COLOR_YELLOWGREEN}"
elif [ $TRUST_SCORE_INT -ge 50 ]; then
    BAR_COLOR="${COLOR_YELLOW}"
elif [ $TRUST_SCORE_INT -ge 25 ]; then
    BAR_COLOR="${COLOR_ORANGE}"
else
    BAR_COLOR="${COLOR_RED}"
fi

# Build the bar with full and empty blocks
BAR="["
if [ $FILLED_WIDTH -gt 0 ]; then
    for ((i=0; i<$FILLED_WIDTH; i++)); do
        # Add gradient effect with different Unicode blocks
        if [ $i -gt $(($FILLED_WIDTH * 4 / 5)) ]; then
            BAR="${BAR}${BAR_COLOR}█${RESET}"
        elif [ $i -gt $(($FILLED_WIDTH * 3 / 5)) ]; then
            BAR="${BAR}${BAR_COLOR}▓${RESET}"
        elif [ $i -gt $(($FILLED_WIDTH * 2 / 5)) ]; then
            BAR="${BAR}${BAR_COLOR}▓${RESET}"
        elif [ $i -gt $(($FILLED_WIDTH * 1 / 5)) ]; then
            BAR="${BAR}${BAR_COLOR}▒${RESET}"
        else
            BAR="${BAR}${BAR_COLOR}░${RESET}"
        fi
    done
fi

# Add empty space
for ((i=0; i<$EMPTY_WIDTH; i++)); do
    BAR="${BAR} "
done
BAR="${BAR}]"

# Display the trust score and bar inside the box
# Calculate exact string length accounting for the trust score digits
SCORE_STR="${TRUST_SCORE_INT}%"
printf "  ${BOLD}Trust Score: ${YELLOW}%s${RESET}\n" "$SCORE_STR"
echo -e "  ${BOLD}Trust Level: ${RESET}$BAR"

# Add interpretative text based on trust score
printf "  ${BOLD}Assessment: ${RESET}"
if [ $TRUST_SCORE_INT -ge 90 ]; then
    ASSESSMENT="Highly Trusted: This IP shows no significant signs of malicious activity"
    printf "${GREEN}%s${RESET}\n" "$ASSESSMENT"
elif [ $TRUST_SCORE_INT -ge 75 ]; then
    ASSESSMENT="Trusted: This IP has minimal presence on blacklists"
    printf "${GREEN}%s${RESET}\n" "$ASSESSMENT"
elif [ $TRUST_SCORE_INT -ge 50 ]; then
    ASSESSMENT="Moderately Trusted: This IP appears on some blacklists but is generally acceptable"
    printf "${YELLOW}%s${RESET}\n" "$ASSESSMENT"
elif [ $TRUST_SCORE_INT -ge 25 ]; then
    ASSESSMENT="Suspicious: This IP appears on several blacklists and should be treated with caution"
    printf "${RED}%s${RESET}\n" "$ASSESSMENT"
else
    ASSESSMENT="Untrusted: This IP appears on many blacklists and is likely engaged in malicious activity"
    printf "${RED}%s${RESET}\n" "$ASSESSMENT"
fi
echo ""

echo -e "\n\n${BOLD}${BLUE}${BOLD} NOTES ${RESET}"
echo ""
CHECK_TIME="• This check was performed at $(date) and reflects the current status."
printf "  ${BOLD}%s${RESET}\n" "$CHECK_TIME"
REPUTATION_NOTE="• IP reputations can change over time."
printf "  ${BOLD}%s${RESET}\n" "$REPUTATION_NOTE"
TRUST_SCORE_NOTE="• The trust score uses a progressive penalty system."
printf "  ${BOLD}%s${RESET}\n" "$TRUST_SCORE_NOTE"
PENALTY_NOTE="• Each additional blacklist appearance results in a larger score reduction."
printf "  ${BOLD}%s${RESET}\n" "$PENALTY_NOTE"
