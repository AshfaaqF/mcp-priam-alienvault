import os
import logging
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from OTXv2 import OTXv2, IndicatorTypes
import datetime


# Load environment variables
load_dotenv()


# Get the OTX API key from environment variables
OTX_API_KEY = os.getenv('OTX_API_KEY')
OTX_SERVER = 'https://otx.alienvault.com/' 

if not OTX_API_KEY:
    logging.error("OTX_API_KEY environment variable not set.")

try:
    otx = OTXv2(api_key=OTX_API_KEY, server=OTX_SERVER)
    logging.info("OTXv2 client initialized successfully.")
except Exception as e:
    logging.error(f"Failed to initialize OTXv2 client: {e}")
    otx = None # Set to None so tools can check if client is available


# Initialize FastMCP
mcp = FastMCP(name="AlienVault OTX MCP Server")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# --- Helper Functions ---

def fetch_otx_data(ioc_type: str, ioc_value: str = None) -> dict:
    """Fetch data from AlienVault OTX API."""
    if not otx:
         return {"error": "OTXv2 client not initialized. API key missing or invalid."}

    try:
        if ioc_type == 'pulses':
            if not ioc_value:
                 return {"error": "Pulse search requires a query string (ioc_value)."}
            logging.info(f"Searching pulses for query: {ioc_value}")
            # OTXv2 search_pulses returns a dictionary containing a list of pulses
            return otx.search_pulses(ioc_value)
        else:
            if not ioc_value:
                 return {"error": f"Indicator type '{ioc_type}' requires an ioc_value."}
            try:
                indicator_type_enum = getattr(IndicatorTypes, ioc_type)
                logging.info(f"Fetching details for {ioc_type}: {ioc_value}")
                # OTXv2 get_indicator_details_full returns a dictionary
                return otx.get_indicator_details_full(indicator_type_enum, ioc_value)
            except AttributeError:
                logging.error(f"Invalid OTX indicator type: {ioc_type}")
                return {"error": f"Invalid OTX indicator type: {ioc_type}"}

    except Exception as e:
        logging.error(f"OTX API request failed for type '{ioc_type}' value '{ioc_value}': {e}")
        return {"error": f"OTX API request failed: {e}"}

def _case_fix(snake_str:str):
    """Helper to convert snake_case to Capitalized Space."""
    spaces = snake_str.replace("_"," ")
    return spaces.capitalize()

def format_otx_output(result: dict, root_key: str = None, indent: int = 0) -> str:
    """
    Recursively format the OTX API output dictionary into a readable string.
    Truncation logic removed.
    """
    if not result:
        return ""

    lines = []
    prefix = "  " * indent

    if root_key:
        title = _case_fix(root_key)
        lines.append(f"\n{prefix}**{title}**:") # Use markdown bold for titles

    if isinstance(result, dict):
        for key, value in result.items():
            if isinstance(value, dict):
                new_lines = format_otx_output(value, key, indent + 1)
                if new_lines:
                     lines.append(new_lines)
            elif isinstance(value, list):
                if value:
                    sub_title = _case_fix(key)
                    lines.append(f"{prefix}  **{sub_title}:**")
                    for i, subvalue in enumerate(value):
                        if isinstance(subvalue, (dict, list)):
                             item_lines = format_otx_output(subvalue, f"Item {i+1}", indent + 2)
                             if item_lines:
                                 lines.append(item_lines)
                        else:
                             lines.append(f"{prefix}    - {subvalue}") # List items with bullet points
                else:
                    lines.append(f"{prefix}  {_case_fix(key)}: empty list")
            else: # basic types: str, int, float, bool, None
                if value is not None:
                    # Special handling for timestamps if needed, similar to VT tool
                    if isinstance(value, int) and ("date" in key or "timestamp" in key):
                         try:
                            dt = datetime.datetime.utcfromtimestamp(value)
                            formatted_value = dt.isoformat() + " UTC"
                         except (ValueError, OSError): # Catch potential errors with timestamp conversion
                            formatted_value = str(value) # Fallback to raw value
                    else:
                        formatted_value = str(value)

                    sub_title = _case_fix(key)
                    lines.append(f"{prefix}  **{sub_title}:** {formatted_value}")


    elif isinstance(result, list):
         # This handles lists at the top level, like pulse search results
         if result:
             lines.append(f"{prefix}**Results:**")
             for i, item in enumerate(result):
                 item_lines = format_otx_output(item, f"Item {i+1}", indent + 1)
                 if item_lines:
                      lines.append(item_lines)
         else:
             lines.append(f"{prefix}No items found.")


    report_string = "\n".join(lines)


    return report_string 



# --- MCP Tool Definitions ---
# Define a tool for each specific IOC type and for pulse search

@mcp.tool("otx_get_ipv4_report")
def otx_get_ipv4_report(ip_address: str) -> str:
    """
    Retrieves the AlienVault OTX report for a given IPv4 address.
    Input: The IPv4 address (e.g., '1.2.3.4').
    """
    data = fetch_otx_data('IPv4', ip_address)
    return format_otx_output(data, "IPv4 Report")

@mcp.tool("otx_get_ipv6_report")
def otx_get_ipv6_report(ipv6_address: str) -> str:
    """
    Retrieves the AlienVault OTX report for a given IPv6 address.
    Input: The IPv6 address (e.g., '2001:0db8:85a3:0000:0000:8a2e:0370:7334').
    """
    data = fetch_otx_data('IPv6', ipv6_address)
    return format_otx_output(data, "IPv6 Report")

@mcp.tool("otx_get_domain_report")
def otx_get_domain_report(domain: str) -> str:
    """
    Retrieves the AlienVault OTX report for a given domain name.
    Input: The domain name (e.g., 'example.com').
    """
    data = fetch_otx_data('DOMAIN', domain)
    return format_otx_output(data, "Domain Report")

@mcp.tool("otx_get_hostname_report")
def otx_get_hostname_report(hostname: str) -> str:
    """
    Retrieves the AlienVault OTX report for a given hostname.
    Input: The hostname (e.g., 'server.example.com').
    """
    data = fetch_otx_data('HOSTNAME', hostname)
    return format_otx_output(data, "Hostname Report")

@mcp.tool("otx_get_url_report")
def otx_get_url_report(url: str) -> str:
    """
    Retrieves the AlienVault OTX report for a given URL.
    Input: The URL (e.g., 'http://example.com/malicious').
    """
    data = fetch_otx_data('URL', url)
    return format_otx_output(data, "URL Report")

@mcp.tool("otx_get_md5_report")
def otx_get_md5_report(file_hash: str) -> str:
    """
    Retrieves the AlienVault OTX report for a given MD5 file hash.
    Input: The MD5 hash (e.g., 'd41d8cd98f00b204e9800998ecf8427e').
    """
    data = fetch_otx_data('FILE_HASH_MD5', file_hash)
    return format_otx_output(data, "MD5 File Hash Report")

@mcp.tool("otx_get_sha1_report")
def otx_get_sha1_report(file_hash: str) -> str:
    """
    Retrieves the AlienVault OTX report for a given SHA-1 file hash.
    Input: The SHA-1 hash (e.g., 'a9993e364706816aba3e25717850c26d9c3d').
    """
    data = fetch_otx_data('FILE_HASH_SHA1', file_hash)
    return format_otx_output(data, "SHA1 File Hash Report")

@mcp.tool("otx_get_sha256_report")
def otx_get_sha256_report(file_hash: str) -> str:
    """
    Retrieves the AlienVault OTX report for a given SHA-256 file hash.
    Input: The SHA-256 hash (e.g., 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').
    """
    data = fetch_otx_data('FILE_HASH_SHA256', file_hash)
    return format_otx_output(data, "SHA256 File Hash Report")

@mcp.tool("otx_get_cve_report")
def otx_get_cve_report(cve_id: str) -> str:
    """
    Retrieves the AlienVault OTX report for a given CVE ID.
    Input: The CVE ID (e.g., 'CVE-2024-12345').
    """
    data = fetch_otx_data('CVE', cve_id)
    return format_otx_output(data, "CVE Report")

@mcp.tool("otx_search_pulses")
def otx_search_pulses(query: str) -> str:
    """
    Searches AlienVault OTX pulses for a given keyword or phrase. Useful for finding information about threat groups, campaigns, or attack types.
    Input: The search query (e.g., 'APT28', 'phishing', 'ransomware as a service').
    """

    data = fetch_otx_data('pulses', query)
    return format_otx_output(data, f"Pulses Search Results for '{query}'")


# --- Run the Server ---

def main():
    """Main function to start the MCP server."""
    logging.info("Starting AlienVault OTX MCP Server...")
  
    if otx: 
        mcp.run()
    else:
        logging.error("OTX client failed to initialize. Server will not start.")

if __name__ == "__main__":
    main()