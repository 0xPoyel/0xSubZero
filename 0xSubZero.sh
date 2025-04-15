#!/bin/bash

# Define colors
WHITE="\033[0;37m"  
RESET="\033[0m" 

# Print ASCII art logo
echo -e "${RED}"
cat << "EOF"
  _____             _____       _      ______               
 |  _  |           /  ___|     | |    |___  /               
 | |/' |_  ________\ `--. _   _| |__     / /  ___ _ __ ___  
 |  /| \ \/ /______|`--. \ | | | '_ \   / /  / _ \ '__/ _ \ 
 \ |_/ />  <       /\__/ / |_| | |_) |./ /__|  __/ | | (_) |
  \___//_/\_\      \____/ \__,_|_.__/ \_____/\___|_|  \___/ v1.0

────────────────────────────────────────────[By 0xPoyel]─────────
EOF
echo -e "${RESET}"

# Variables
DOMAIN=$1
OUTPUT_DIR="subdomain_$DOMAIN$(date +-%Y-%m-%d_%H:%M:%S)"
LOGFILE="$OUTPUT_DIR/tools_processing.log"
API_KEYS_FILE="Config/api_keys.txt"
WORDLIST_DIR="wordlists"

# Function: Display Help
function display_help() {
    echo -e "\033[1;34mSubdomain Enumeration - Help Menu\033[0m"
    echo -e "\033[1;33mUsage:\033[0m ./0xSubZero.sh <domain>"
    echo -e "\nOptions:"
    echo "  <domain>          Run the subdomain enumeration for the specified dsomain."
    echo "  -c, --check       Check if all required tools are installed."
    echo "  -i, --install     Install all required tools."
    echo "  -a, --apikey      Validate that all required API keys are present."
    echo "  -h, --help        Display this help menu."
    echo -e "\nExamples:"
    echo "  ./script.sh example.com"
    echo "  ./0xSubZero.sh -c"
    echo "  ./0xSubZero.sh -i"
    echo "  ./0xSubZero.sh -a"
}

# Function: Check Required Tools
function check_tools() {
    echo -e "\033[1;34mChecking Required Tools...\033[0m"
    REQUIRED_TOOLS=("subfinder" "assetfinder" "amass" "findomain" "gau" "httpx" "gobuster" "unfurl" "github-subdomains" "chaos" "shosubgo" )
    for tool in "${REQUIRED_TOOLS[@]}"; do
        command -v $tool &>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "\033[1;31m$tool is not installed.\033[0m"
            MISSING=true
        else
            echo -e "\033[1;32m$tool is installed.\033[0m"
        fi
    done
    if [ "$MISSING" = true ]; then
        echo -e "\033[1;33mSome tools are missing. Run './script.sh -i' to install them.\033[0m"
        exit 1
    fi
}

# Function: Install Required Tools
function install_tools() {
    echo -e "\033[1;34mInstalling Required Tools...\033[0m"

    # Array of required tools
    tools=("subfinder" "assetfinder" "amass" "findomain" "gau" "httpx" "gobuster" "unfurl" "github-subdomains" "chaos" "shosubgo" "gobuster" )

    # Loop through each tool
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "\033[1;33mInstalling $tool...\033[0m"
            
            # Ensure the script name and tool variable are spaced correctly
            if sudo bash ./install.sh "$tool" &>/dev/null; then
                echo -e "\033[1;33m$tool installed successfully.\033[0m"
            else
                echo -e "\033[1;31mFailed to install $tool. Please install it manually.\033[0m"
            fi
        else
            echo -e $tool ---------- "\033[1;32m is already installed.\033[0m"
        fi
    done

    echo -e "\033[1;33mAll tools processed successfully.\033[0m"
}


# Function: Validate API Keys
function check_api_keys() {
    echo -e "\033[1;34mValidating API Keys...\033[0m"
    if [ ! -f "$API_KEYS_FILE" ]; then
        echo -e "\033[1;31mAPI keys file ($API_KEYS_FILE) not found.\033[0m"
        exit 1
    fi

    GITHUB_TOKEN=$(grep "GITHUB_TOKEN" "$API_KEYS_FILE" | cut -d '=' -f2 | tr -d ' ')
    CHAOS_API_KEY=$(grep "CHAOS_API_KEY" "$API_KEYS_FILE" | cut -d '=' -f2 | tr -d ' ')
    SHODAN_API_KEY=$(grep "SHODAN_API_KEY" "$API_KEYS_FILE" | cut -d '=' -f2 | tr -d ' ')
    VIRUSTOTAL_API_KEY=$(grep "VIRUSTOTAL_API_KEY" "$API_KEYS_FILE" | cut -d '=' -f2 | tr -d ' ')

    if [ -z "$GITHUB_TOKEN" ] || [ -z "$CHAOS_API_KEY" ] || [ -z "$SHODAN_API_KEY" ]; then
        echo -e "\033[1;31mOne or more API keys are missing.\033[0m"
        exit 1
    fi
    echo -e "\033[1;32mAll API keys are present.\033[0m"
}

# Main Logic
if [ "$DOMAIN" == "-h" ] || [ "$DOMAIN" == "--help" ]; then
    display_help
    exit 0
elif [ "$DOMAIN" == "-c" ] || [ "$DOMAIN" == "--check" ]; then
    check_tools
    exit 0
elif [ "$DOMAIN" == "-i" ] || [ "$DOMAIN" == "--install" ]; then
    install_tools
    exit 0
elif [ "$DOMAIN" == "-a" ] || [ "$DOMAIN" == "--apikey" ]; then
    check_api_keys
    exit 0
elif [ -z "$DOMAIN" ]; then
    echo -e "\033[1;31mPlease provide a valid option or domain.\033[0m"
    display_help
    exit 1
else
    echo -e "\033[1;34mStarting Subdomain Enumeration for $DOMAIN\033[0m"
    mkdir -p "$OUTPUT_DIR"
    # Add main enumeration logic here
    echo -e "\033[1;32mEnumeration completed. Check $OUTPUT_DIR for results.\033[0m"
fi

# Define log file in the output directory
LOGFILE="$OUTPUT_DIR/tools_processing.log"

# Ensure the API keys file is provided and exists
API_KEYS_FILE="Config/api_keys.txt"
if [ ! -f "$API_KEYS_FILE" ]; then
    echo -e "\033[1;31mAPI keys file ($API_KEYS_FILE) not found. Create a file with GITHUB_TOKEN, CHAOS_API_KEY, and SHODAN_API_KEY.\033[0m"
    exit 1
fi

# Read API keys from file
GITHUB_TOKEN=$(grep "GITHUB_TOKEN" "$API_KEYS_FILE" | cut -d '=' -f2 | tr -d ' ')
CHAOS_API_KEY=$(grep "CHAOS_API_KEY" "$API_KEYS_FILE" | cut -d '=' -f2 | tr -d ' ')
SHODAN_API_KEY=$(grep "SHODAN_API_KEY" "$API_KEYS_FILE" | cut -d '=' -f2 | tr -d ' ')
VIRUSTOTAL_API_KEY=$(grep "VIRUSTOTAL_API_KEY" "$API_KEYS_FILE" | cut -d '=' -f2 | tr -d ' ')


# Validate API keys
if [ -z "$GITHUB_TOKEN" ] || [ -z "$CHAOS_API_KEY" ] || [ -z "$SHODAN_API_KEY" ] || [ -z "$VIRUSTOTAL_API_KEY" ]; then
    echo -e "\033[1;31mOne or more API keys are missing in $API_KEYS_FILE.\033[0m"
    exit 1
fi

# Before running Gobuster, check if the directory exists:
if [ ! -d "$WORDLIST_DIR" ]; then
    echo "Error: Wordlist directory '$WORDLIST_DIR' does not exist." >&2
    exit 1
fi

# Function to check network connectivity
check_network() {
  echo -e "\033[1;33m[+] Checking network connectivity...\033[0m"
  while ! ping -c 1 -q google.com &>/dev/null; do
    echo -e "\033[1;31m[-] Network is offline. Retrying in 10 seconds...\033[0m"
    sleep 10
  done
  echo -e "\033[1;32m[+] Network is online. Proceeding...\033[0m"
}

# Display a message to start subdomain enumeration
echo -e "\033[1;32mStarting Subdomain Enumeration for $DOMAIN\033[0m"

# Function to check if a command is available
check_command() {
    command -v $1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "\033[1;31m$1 is not installed. Please install it before proceeding.\033[0m"
        exit 1
    fi
}

# Subdomain enumeration tools running concurrently with output redirection
echo -e "\033[1;32mPassive Enumeration\033[0m" | tee -a "$LOGFILE"

echo -e "\033[1;32mRunning Subfinder\033[0m"
subfinder -d $DOMAIN -all -recursive -silent -o "$OUTPUT_DIR/1_subfinder.txt" &

echo -e "\033[1;32mRunning Assetfinder\033[0m"
assetfinder --subs-only $DOMAIN | tee "$OUTPUT_DIR/2_assetfinder.txt" &

echo -e "\033[1;32mRunning GitHub Subdomains\033[0m"
github-subdomains -d $DOMAIN -t "$GITHUB_TOKEN" -o "$OUTPUT_DIR/4_githubsub.txt" &

echo -e "\033[1;32mRunning Chaos\033[0m"
chaos -d $DOMAIN -key "$CHAOS_API_KEY" -o "$OUTPUT_DIR/5_chaos.txt" -v &

echo -e "\033[1;32mRunning Amass\033[0m"
amass enum -passive -norecursive -noalts -d $DOMAIN -o "$OUTPUT_DIR/6_amass.txt" &

echo -e "\033[1;32mRunning Findomain\033[0m"
findomain --target $DOMAIN --unique-output "$OUTPUT_DIR/7_findomain.txt" &

echo -e "\033[1;32mRunning Gau\033[0m"
gau --threads 10 --subs $DOMAIN | unfurl -u domains > "$OUTPUT_DIR/8_gau.txt" &

echo -e "\033[1;32mRunning Shosubgo\033[0m"
shosubgo -d $1 -s "$SHODAN_API_KEY" | tee "$OUTPUT_DIR/9_shosubgo.txt" &

# Wait for all background processes to finish
wait

# Merge and sort the results, remove duplicates
echo -e "\033[1;32mMerge and sort the results, remove duplicates\033[0m" | tee -a "$LOGFILE"
echo -e "\033[1;34mMerging Subdomains\033[0m"
cat "$OUTPUT_DIR/1_subfinder.txt" "$OUTPUT_DIR/2_assetfinder.txt" "$OUTPUT_DIR/4_githubsub.txt" "$OUTPUT_DIR/5_chaos.txt" "$OUTPUT_DIR/6_amass.txt" "$OUTPUT_DIR/7_findomain.txt" "$OUTPUT_DIR/8_gau.txt"  "$OUTPUT_DIR/9_shosubgo.txt" | sort | uniq | grep "$DOMAIN"> "$OUTPUT_DIR/passive_subdomains.txt"


# Additional methods using CURL
echo -e "\033[1;32mAdditional methods Enumeration\033[0m" | tee -a "$LOGFILE"

echo -e "\033[1;32mcurl\033[0m"
curl -sk "https://crt.sh/?q=%.$DOMAIN&output=json" | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | grep -w "$DOMAIN\$" | anew "$OUTPUT_DIR/1_crt.txt"  &

echo -e "\033[1;32mjldc\033[0m"
curl -sk "https://jldc.me/anubis/subdomains/$DOMAIN" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew "$OUTPUT_DIR/2_jldc.txt" &

echo -e "\033[1;32msubdomain\033[0m"
curl "https://api.subdomain.center/?domain=$1" -s | jq -r '.[]' | sort -u | anew | anew "$OUTPUT_DIR/3_subdomain.txt" &

echo -e "\033[1;32mcertspotter\033[0m"
curl -sk "https://api.certspotter.com/v1/issuances?domain=$1&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | anew "$OUTPUT_DIR/4_certspotter.txt" &

echo -e "\033[1;32mvirustotal\033[0m"
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VIRUSTOTAL_API_KEY&domain=$1" | jq | egrep -v "http|Alexa domain info" | grep "$1" | sed 's/[",]//g' | sed 's/^[[:space:]]*//' | anew "$OUTPUT_DIR/5_virustotal.txt"

# Wait for all background processes to complete
wait

# Combine and deduplicate results
echo -e "\033[1;32mACombine and deduplicate results\033[0m" | tee -a "$LOGFILE"
cat "$OUTPUT_DIR/1_crt.txt" "$OUTPUT_DIR/2_jldc.txt" "$OUTPUT_DIR/3_subdomain.txt" "$OUTPUT_DIR/4_certspotter.txt" "$OUTPUT_DIR/5_virustotal.txt"  | sort | uniq | grep "$DOMAIN"> "$OUTPUT_DIR/Additional_Methods.txt"

# Clean up individual tool output files
echo -e "\033[1;32mCleaning Up Temporary Files\033[0m"
rm "$OUTPUT_DIR/1_crt.txt" "$OUTPUT_DIR/2_jldc.txt" "$OUTPUT_DIR/3_subdomain.txt" "$OUTPUT_DIR/4_certspotter.txt" "$OUTPUT_DIR/5_virustotal.txt" 

# Active Subdomain Enumeration using Gobuster
echo -e "\033[1;32mActive Subdomain Enumeration Using Gobuster\033[0m" | tee -a "$LOGFILE"

gobuster dns -d $DOMAIN -t 100 -w $WORDLIST_DIR/*.txt -o "$OUTPUT_DIR/gobuster_results.txt"
cat "$OUTPUT_DIR/gobuster_results.txt" | grep -oP '(?<=Found: )[^ ]+' >> "$OUTPUT_DIR/gobuster_subdomains.txt"

# Combine and deduplicate results
cat "$OUTPUT_DIR/Additional_Methods.txt" "$OUTPUT_DIR/gobuster_subdomains.txt" "$OUTPUT_DIR/passive_subdomains.txt"| sort | uniq | grep "$DOMAIN"> "$OUTPUT_DIR/ALL_Subdomains.txt"

# Identify alive Subdomains 
echo -e "\033[1;32mIdentify alive Subdomains Using httpx\033[0m" | tee -a "$LOGFILE"
cat "$OUTPUT_DIR/ALL_Subdomains.txt" | httpx -follow-host-redirects -random-agent -status-code -silent -retries 2 -title -web-server -ip -tech-detect -location -rl 30 -o "$OUTPUT_DIR/webs_info.txt" 
cat "$OUTPUT_DIR/webs_info.txt"  | cut -d ' ' -f1 | grep ".$1" | sort -u > "$OUTPUT_DIR/Alive_Subdomains.txt"

# Final message indicating the process is done
echo -e ""
echo -e "\033[1;30mSubdomain Enumeration Completed\033[0m"

# HTML Report Generation
echo -e "\033[1;32mGenerating HTML Report...\033[0m" | tee -a "$LOGFILE"

generate_html_report() {
    local output_file="$OUTPUT_DIR/Subdomains_Report.html"

    # Start HTML file
    echo "<html><head><title>Subdomain Enumeration Report</title>" > "$output_file"
    
    # Add CSS Styling for better readability
    echo "<style>
        body { font-family: Arial, sans-serif; text-align: center; }
        h2 { color: #2E8B57; }
        table { width: 90%; margin: auto; border-collapse: collapse; }
        th, td { border: 1px solid black; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>" >> "$output_file"

    echo "</head><body>" >> "$output_file"
    echo "<h2>Subdomain Enumeration Report</h2>" >> "$output_file"
    echo "<table>" >> "$output_file"
    echo "<tr><th>S.No.</th><th>Subdomain</th><th>Status Code</th><th>Title</th><th>IP Address</th><th>Web Server</th><th>Technologies</th><th>Redirect URL</th></tr>" >> "$output_file"

    # Initialize serial number counter
    serial_number=1

    # Process each line in webs_info.txt
    while IFS= read -r line; do
        # Remove ANSI color codes
        clean_line=$(echo "$line" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')

        # Extract fields
        subdomain=$(echo "$clean_line" | awk '{print $1}')
        status=$(echo "$clean_line" | awk '{print $2}')
        title=$(echo "$clean_line" | grep -oP '(?<=\[)[^\]]+(?=\])' | sed -n '2p')  # Extract the second value in brackets (title)
        ip=$(echo "$clean_line" | awk '{print $NF}')
        web=$(echo "$clean_line" | grep -oP '(?<=\[)[^\]]+(?=\])' | sed -n '3p')  # Extract third value in brackets (Web Server)
        tech=$(echo "$clean_line" | grep -oP '(?<=\[)[^\]]+(?=\])' | sed -n '4p')  # Extract fourth value in brackets (Technologies)
        redirect=$(echo "$clean_line" | grep -oP '(?<=\[)[^\]]+(?=\])' | sed -n '5p')  # Extract fifth value (Redirect URL)

        # Ensure missing fields are replaced with "N/A"
        status=${status:-"N/A"}
        title=${title:-"N/A"}
        ip=${ip:-"N/A"}
        web=${web:-"N/A"}
        tech=${tech:-"N/A"}
        redirect=${redirect:-"N/A"}

        # Append row to HTML table
        echo "<tr><td>$serial_number</td><td>$subdomain</td><td>$status</td><td>$title</td><td>$ip</td><td>$web</td><td>$tech</td><td>$redirect</td></tr>" >> "$output_file"

        # Increment serial number
        ((serial_number++))
    done < "$OUTPUT_DIR/webs_info.txt"

    # Close HTML tags
    echo "</table></body></html>" >> "$output_file"
    echo -e "\033[1;32m[+] HTML Report Generated: $output_file\033[0m"
}

# Call function after CSV generation
generate_html_report



# Print ASCII art logo
echo -e "${RED}"
cat << "EOF"
  _____             _____       _      ______               
 |  _  |           /  ___|     | |    |___  /               
 | |/' |_  ________\ `--. _   _| |__     / /  ___ _ __ ___  
 |  /| \ \/ /______|`--. \ | | | '_ \   / /  / _ \ '__/ _ \ 
 \ |_/ />  <       /\__/ / |_| | |_) |./ /__|  __/ | | (_) |
  \___//_/\_\      \____/ \__,_|_.__/ \_____/\___|_|  \___/ v1.0

────────────────────────────────────--------─[By 0xPoyel]──------
EOF
echo -e "${RESET}"

# Final Report
echo -e ""
echo -e "\033[1;41m Final Report [$DOMAIN]\033[0m"

# Total passive Subdomain enumeration
total_subdomains=$(wc -l < "$OUTPUT_DIR/passive_subdomains.txt" ) 
echo -e "\033[1;34m[+++] Total Passive Enumeration:\033[0m \033[1;37m$total_subdomains"

total_subdomains=$(wc -l < "$OUTPUT_DIR/1_subfinder.txt" ) 
echo -e "\033[1;33m[+]subfinder:\033[0m \033[1;37m$total_subdomains"
total_subdomains=$(wc -l < "$OUTPUT_DIR/2_assetfinder.txt") 
echo -e "\033[1;33m[+]assetfinder:\033[0m \033[1;37m$total_subdomains"
total_subdomains=$(wc -l < "$OUTPUT_DIR/4_githubsub.txt") 
echo -e "\033[1;33m[+]github-subdomains:\033[0m \033[1;37m$total_subdomains"
total_subdomains=$(wc -l < "$OUTPUT_DIR/5_chaos.txt") 
echo -e "\033[1;33m[+]chaos:\033[0m \033[1;37m$total_subdomains"
total_subdomains=$(wc -l < "$OUTPUT_DIR/6_amass.txt") 
echo -e "\033[1;33m[+]amass:\033[0m \033[1;37m$total_subdomains"
total_subdomains=$(wc -l < "$OUTPUT_DIR/7_findomain.txt" ) 
echo -e "\033[1;33m[+]findomain:\033[0m \033[1;37m$total_subdomains"
total_subdomains=$(wc -l < "$OUTPUT_DIR/8_gau.txt") 
echo -e "\033[1;33m[+]gau:\033[0m \033[1;37m$total_subdomains"
total_subdomains=$(wc -l < "$OUTPUT_DIR/9_shosubgo.txt") 
echo -e "\033[1;33m[+]shosubgo:\033[0m \033[1;37m$total_subdomains"

echo -e ""

# Total Additional Subdomain enumeration
total_subdomains=$(wc -l < "$OUTPUT_DIR/Additional_Methods.txt" ) 
echo -e "\033[1;32m[++]Total Additional Subdomain enumeration:\033[0m \033[1;37m$total_subdomains"

# Total Active Subdomain enumeration
go_total_subdomains=$(wc -l < "$OUTPUT_DIR/gobuster_subdomains.txt") 
echo -e "\033[1;31m[++]Total Active Subdomain enumeration:\033[0m \033[1;37m$go_total_subdomains"

# Clean up individual tool output filess
rm "$OUTPUT_DIR/1_subfinder.txt" "$OUTPUT_DIR/2_assetfinder.txt" "$OUTPUT_DIR/4_githubsub.txt" "$OUTPUT_DIR/5_chaos.txt" "$OUTPUT_DIR/6_amass.txt" "$OUTPUT_DIR/7_findomain.txt" "$OUTPUT_DIR/8_gau.txt"  "$OUTPUT_DIR/9_shosubgo.txt" "$OUTPUT_DIR/gobuster_subdomains.txt" "$OUTPUT_DIR/Additional_Methods.txt" "$OUTPUT_DIR/passive_subdomains.txt" "$OUTPUT_DIR/gobuster_results.txt"

echo -e ""
echo -e "\033[1;40mFinal Result\033[0m"

total_subdomains_Found=$(wc -l < "$OUTPUT_DIR/ALL_Subdomains.txt")
echo -e "\033[1;37m[0xSubZero] Total Subdomains Found:---\033[0m \033[1;32m$total_subdomains_Found"

total_subdomains=$(wc -l < "$OUTPUT_DIR/Alive_Subdomains.txt")
echo -e "\033[1;33m[0xSubZero] Total Alive Subdomains Found:---\033[0m \033[1;31m$total_subdomains"
echo -e ""

# Final message indicating the process is done
echo -e "\033[1;30mOutput Files\033[0m"
echo -e "- "ALL_Subdomains.txt""
echo -e "- "webs_info.txt""
echo -e "- "Alive_Subdomains.txt""
echo -e "- "Subdomains_Report.html""
