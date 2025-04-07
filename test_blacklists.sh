#!/bin/bash

# test_blacklists.sh - Test DNS blacklist services for availability
# This script checks each blacklist service with a simple DNS lookup
# and reports which ones are unreachable or not responding properly

# Set colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${YELLOW}${BOLD}Testing DNS blacklist services for availability and blacklist detection...${NC}\n"

# Create arrays to store results
declare -a working_services=()
declare -a detecting_services=()
declare -a failed_services=()

# Test an individual blacklist service
test_blacklist() {
    local service=$1
    local test_ip="127.0.0.2" # Commonly blacklisted IP for testing
    
    # Get reversed IP for testing
    local reversed_ip=$(echo $test_ip | awk -F. '{print $4"."$3"."$2"."$1}')
    
    # Perform DNS lookup test like check_ip_blacklist.sh does
    result=$(host -W 3 "${reversed_ip}.${service}" 2>&1)
    
    printf "%-40s" "$service"
    
    if [[ $? -eq 0 ]]; then
        working_services+=("$service")
        
        # Check if the IP is actually listed (using same logic as check_ip_blacklist.sh)
        if [[ $result == *"has address"* || $result == *"domain name pointer"* ]]; then
            detecting_services+=("$service")
            echo -e "${RED}[BLACKLISTED]${NC}"
        else
            echo -e "${GREEN}[WORKING]${NC}"
        fi
    else
        failed_services+=("$service")
        echo -e "${RED}[UNREACHABLE]${NC}"
    fi
}

# List of blacklist services to check
blacklist_services=(
"dnsbl-0.uceprotect.net"
"dnsbl-1.uceprotect.net"
"dnsbl-2.uceprotect.net"
"dnsbl-3.uceprotect.net"
"spam.dnsbl.sorbs.net"
"rbl.abuse.ro"
"spam.dnsbl.anonmails.de"
"aspews.ext.sorbs.net"
"ips.backscatterer.org"
"b.barracudacentral.org"
"l1.bbfh.ext.sorbs.net"
"l2.bbfh.ext.sorbs.net"
"l3.bbfh.ext.sorbs.net"
"l4.bbfh.ext.sorbs.net"
"bl.blocklist.de"
"bsb.empty.us"
"bsb.spamlookup.net"
"dnsbl.calivent.com.pe"
"cbl.anti-spam.org.cn"
"cdl.anti-spam.org.cn"
"cbl.abuseat.org"
"bogons.cymru.com"
"torexit.dan.me.uk"
"bl.drmx.org"
"dnsbl.dronebl.org"
"spamsources.fabel.dk"
"spamrbl.imp.ch"
"wormrbl.imp.ch"
"hil.habeas.com"
"dnsbl.inps.de"
"rbl.interserver.net"
"mail-abuse.blacklist.jippg.org"
"dnsbl.kempt.net"
"bl.konstant.no"
"spamguard.leadmon.net"
"z.mailspike.net"
"bl.mailspike.net"
"phishing.rbl.msrbl.net"
"spam.rbl.msrbl.net"
"relays.nether.net"
"unsure.nether.net"
"ix.dnsbl.manitu.net"
"orvedb.aupads.org"
"psbl.surriel.com"
"dyna.spamrats.com"
"noptr.spamrats.com"
"spam.spamrats.com"
"all.rbl.jp"
"rsbl.aupads.org"
"rbl.schulte.org"
"exitnodes.tor.dnsbl.sectoor.de"
"backscatter.spameatingmonkey.net"
"bl.spameatingmonkey.net"
"dnsbl.sorbs.net"
"http.dnsbl.sorbs.net"
"misc.dnsbl.sorbs.net"
"smtp.dnsbl.sorbs.net"
"socks.dnsbl.sorbs.net"
"zombie.dnsbl.sorbs.net"
"dul.dnsbl.sorbs.net"
"block.dnsbl.sorbs.net"
"bl.spamcop.net"
"zen.spamhaus.org"
"aspews.ext.sorbs.net"
"bl.suomispam.net"
"dnsrbl.swinog.ch"
"rbl2.triumf.ca"
"truncate.gbudb.net"
"blacklist.woody.ch"
"db.wpbl.info"
"dnsbl.zapbl.net"
"rhsbl.zapbl.net"
"dnsbl.spfbl.net"
)

# If check_ip_blacklist.sh exists, extract blacklist entries from it
if [ -f "check_ip_blacklist.sh" ]; then
    echo -e "${YELLOW}Extracting blacklist services from check_ip_blacklist.sh...${NC}\n"
    
    # Extract domains from check_ip_blacklist.sh
    # This assumes the domains are in the format "domain:description" in an array
    extracted_services=$(grep -o '"[^:]*:' check_ip_blacklist.sh | sed 's/[":]//g')
    
    if [ -n "$extracted_services" ]; then
        # Convert to array
        readarray -t extracted_array <<< "$extracted_services"
        
        # Merge with existing list, avoiding duplicates
        for service in "${extracted_array[@]}"; do
            if [[ ! " ${blacklist_services[@]} " =~ " ${service} " ]]; then
                blacklist_services+=("$service")
            fi
        done
        
        echo -e "Found $(wc -l <<< "$extracted_services") services in check_ip_blacklist.sh\n"
    else
        echo -e "${YELLOW}No services found in check_ip_blacklist.sh or format not recognized${NC}\n"
    fi
fi

echo -e "${YELLOW}${BOLD}Testing ${#blacklist_services[@]} blacklist services with IP 127.0.0.2...${NC}\n"
echo -e "Service                                   Result"
echo -e "-------------------------------------------------------------------------"

# Test each blacklist service
for service in "${blacklist_services[@]}"; do
    test_blacklist "$service"
done

# Display summary
echo -e "\n${BOLD}${BLUE}========== SUMMARY ==========${NC}"
echo -e "${GREEN}Working services: ${#working_services[@]}/${#blacklist_services[@]}${NC}"
echo -e "${RED}Services detecting 127.0.0.2 as blacklisted: ${#detecting_services[@]}/${#blacklist_services[@]}${NC}"
echo -e "${RED}Unreachable services: ${#failed_services[@]}/${#blacklist_services[@]}${NC}"

if [ ${#detecting_services[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}${BOLD}Services that detected 127.0.0.2 as blacklisted:${NC}"
    for service in "${detecting_services[@]}"; do
        echo "- $service"
    done
fi

if [ ${#working_services[@]} -gt 0 ]; then
    echo -e "\n${GREEN}${BOLD}Reachable services not detecting 127.0.0.2:${NC}"
    for service in "${working_services[@]}"; do
        if [[ ! " ${detecting_services[@]} " =~ " ${service} " ]]; then
            echo "- $service"
        fi
    done
fi

if [ ${#failed_services[@]} -gt 0 ]; then
    echo -e "\n${RED}${BOLD}Unreachable services:${NC}"
    for service in "${failed_services[@]}"; do
        echo "- $service"
    done
    
    echo -e "\n${YELLOW}You may want to consider removing unreachable services from check_ip_blacklist.sh${NC}"
fi

echo -e "\n${YELLOW}${BOLD}RECOMMENDATION:${NC}"
echo -e "The services that detected 127.0.0.2 as blacklisted are working properly and should be kept."
echo -e "Services that are reachable but don't detect 127.0.0.2 may still be functional but have different policies."
echo -e "Consider removing unreachable services from your check_ip_blacklist.sh script."

echo -e "\n${YELLOW}Test completed at $(date).${NC}"

