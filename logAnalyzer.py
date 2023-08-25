import requests
import re
from bs4 import BeautifulSoup

class IPAnalyzer:
    """
    IPAnalyzer is a class designed to analyze and extract information related to IP addresses and Windows events.

    It provides methods to search for IP information based on specified actions, extract information from logs,
    search for Windows event status information, and more.

    Attributes:
        ABUSE_IP_DB_URL (str): URL for the AbuseIPDB API.
        ABUSE_IP_DB_HEADERS (dict): Headers for the AbuseIPDB API.
        VIRUS_TOTAL_URL (str): URL for the VirusTotal API.
        VIRUS_TOTAL_HEADERS (dict): Headers for the VirusTotal API.
        IP_LOCATION_URL (str): URL for the IP location API.
        WINDOWS_SECURITY_URL (str): URL for the Windows Security Encyclopedia.
        SECURITY_IDENTIFIERS_URL (str): URL for the Microsoft Security Identifiers page.
        ENCYCLOPEDIA_URL (str): URL for the Windows Security Encyclopedia.
    """

    ABUSE_IP_DB_URL = 'https://api.abuseipdb.com/api/v2/check'
    ABUSE_IP_DB_HEADERS = {'Accept': 'application/json', 'Key': 'API_KEY'}
    VIRUS_TOTAL_URL = 'https://www.virustotal.com/api/v3/ip_addresses/{}'
    VIRUS_TOTAL_HEADERS = {"accept": "application/json", "x-apikey": "API_KEY"}
    IP_LOCATION_URL = 'https://api.iplocation.net/?ip={}'
    WINDOWS_SECURITY_URL = 'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={}'
    SECURITY_IDENTIFIERS_URL = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"
    ENCYCLOPEDIA_URL = "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/"

    def __init__(self):
        pass

    def search_ip(self, ip, action):
        
        """
            
    Searches for IP information based on the specified action.

    :param ip: The IP address to search for.
    :param action: The action to perform. Can be "abuseipdb", "virustotal", or "iplocation".
    :return: A string containing the result of the search.
    :raises ValueError: If an invalid action is specified.
            
        """
        result = ""
        try :
            
            if action == "abuseipdb":
                url = self.ABUSE_IP_DB_URL
                querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
                headers = self.ABUSE_IP_DB_HEADERS
                response = requests.get(url, headers=headers, params=querystring)
                if response.status_code == 200:
                    data = response.json()['data']
                    print("****************************************** AbuseIPDB *****************************************************************")
                    
                    result += f"Abuse Confidence Score: {data['abuseConfidenceScore']}\n"
                    result += f"Country Code: {data['countryCode']}\n"
                    result += f"Domain: {data['domain']}\n"
                    result += f"Is Tor: {data['isTor']}\n"
                    result += f"Is Whitelisted: {data['isWhitelisted']}\n"
                    result += f"ISP: {data['isp']}\n"
                    result += f"Total Reports: {data['totalReports']}\n"
                else:
                    result += "Failed to retrieve data from AbuseIPDB API\n"

            elif action == "virustotal":
                try:
                    # Constructing the URL and headers for the VirusTotal API
                    url = self.VIRUS_TOTAL_URL.format(ip)
                    headers = self.VIRUS_TOTAL_HEADERS

                    # Sending a GET request to the VirusTotal API
                    response = requests.get(url, headers=headers,timeout=15)

                    # Checking if the response status code is 200 (OK)
                    if response.status_code != 200:
                        raise Exception("Failed to retrieve data from VirusTotal API")

                    # Parsing the JSON response
                    data = response.json()

                    # Extracting the 'last_analysis_stats' attribute
                    last_analysis_stats = data['data']['attributes']['last_analysis_stats']

                    # Printing a header for the VirusTotal stats
                    print("****************************************** Virus total stats *************************************************************")

                    # Iterating through the keys and values in 'last_analysis_stats' and appending them to the result string
                    for key, value in last_analysis_stats.items():
                        result += f"{key.capitalize()}: {value}\n"
                except Exception as error:
                    # Handling any exceptions that may occur and appending an error message to the result string
                    result += f"An error occurred while retrieving data from VirusTotal: {str(error)}\n"

            elif action == "iplocation":
                try:
                    # Constructing the URL for the IP location API
                    url = self.IP_LOCATION_URL.format(ip)

                    # Sending a GET request to the IP location API
                    response = requests.get(url)

                    # Checking if the response status code is 200 (OK)
                    if response.status_code != 200:
                        raise Exception("Failed to retrieve IP location data")

                    # Parsing the JSON response
                    data = response.json()

                    # Printing a header for the IP location stats
                    print("****************************************** Iplocation *************************************************************")

                    # Extracting and appending the details to the result string
                    result += f"Country Name: {data.get('country_name', 'N/A')}\n"
                    result += f"Country Code: {data.get('country_code2', 'N/A')}\n"
                    result += f"ISP: {data.get('isp', 'N/A')}\n"
                except Exception as e:
                    # Handling any exceptions that may occur and appending an error message to the result string
                    result += f"An error occurred while retrieving data from IP location: {str(e)}\n"

            else:
                raise ValueError("Invalid action specified")

        except requests.RequestException as e:
            result += f"An error occurred while retrieving data: {str(e)}\n"

        return result

    def search_windows_code_status(self, event_id, status_code):
        """
        Searches for Windows event status information based on the given event ID and status code.

        :param event_id: The Windows event ID to search for.
        :param status_code: The status code to retrieve information about.
        :return: A string containing the result of the search or an error message.
        """
        url = self.WINDOWS_SECURITY_URL.format(event_id)
        result_string = ""
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            tables = soup.find_all('table')  # Find all tables in the page
        
            for table in tables:
                rows = table.select('tbody tr')
                status_dict = {}
            
                for row in rows:
                    row_status_code = row.select_one('td:nth-child(1)').get_text().strip()
                    description = row.select_one('td:nth-child(2)').get_text().strip()
                    more_cell = row.select_one('td:nth-child(3)')
                    if more_cell:
                        more = more_cell.get_text().strip()
                    else:
                        more = "No more info"
                
                    status_dict[row_status_code] = (description, more)
                
                if status_code in status_dict:
                
                    print("****************************************** Windows events *************************************************************")
                    result_string += f"Status Code: {status_code}\n"
                    result_string += f"Description: {status_dict[status_code][0]}\n"
                    result_string += f"More infos: {status_dict[status_code][1]}\n"
                    break  # Exit loop when code is found
                else:
                    pass
            return result_string
            

        except requests.RequestException as e:
            return f"Failed to retrieve data from the page: {str(e)}\n"
         

    def extract_info_from_log(self, log):
        """
        Extracts information from a given log.

        This method extracts IP addresses, event IDs, status codes, security identifiers (SIDs), and the number of events
        from the provided log.

        :param log: The log text to analyze.
        :return: A tuple containing:
            - A list of unique IP addresses found in the log.
            - A dictionary mapping event IDs to corresponding status codes.
            - A list of unique SIDs found in the log.
            - The number of events found in the log, or -1 if not found.
        """
        try:
            # Define patterns for matching different components in the log
            patterns = {
                'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'event_id': r'(?<=\s)(\d{4})(?=\s)',
                'status_code': r'(?:0x[0-9A-Fa-f]{1,8})',
                'sid': r'(S-\S+)(?<!-)',
                'events': r'\[Events - (\d+)\]'
            }

            # Extract information using regular expressions
            ip_addresses = list(set(re.findall(patterns['ip'], log)))
            event_ids = list(set(re.findall(patterns['event_id'], log)))
            status_codes = list(set(re.findall(patterns['status_code'], log)))
            sids = list(set(re.findall(patterns['sid'], log)))
            events_match = re.search(patterns['events'], log)
            num_events = int(events_match.group(1)) if events_match else -1

            # Filter event IDs based on length
            filtered_event_ids = [event_id for event_id in event_ids if len(event_id) == 4]

            # Create a dictionary mapping event IDs to corresponding status codes
            event_info = {event_id: tuple(status_codes) for event_id in filtered_event_ids}

            return ip_addresses, event_info, sids, num_events
        except Exception as e:
            # Handle any exceptions that may occur during extraction
            print(f"An error occurred while extracting information from the log: {str(e)}")
            return None

    def extract_info_from_table(self, identifier):
        divise = identifier.split("-")

        while len(divise[-1]) > 3:
            divise.pop()
            identifier = "-".join(divise)

        if identifier.endswith("-") or not identifier[-1].isdigit():
            identifier = identifier.rstrip("-")

        url = self.SECURITY_IDENTIFIERS_URL
        response = requests.get(url,timeout=10)

        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            tables = soup.find_all('table')  # Find all tables in the page

            for table in tables:
                rows = table.select('tbody tr')
                for row in rows:
                    identifier_cell = row.select_one('td:nth-child(1)').get_text().strip()
                    if identifier_cell == identifier:
                        col2 = row.select_one('td:nth-child(2)').get_text().strip()
                        col3 = row.select_one('td:nth-child(3)').get_text().strip()
                        return col2, col3

                base_identifier = "-".join(identifier.split("-")[:-1])
                for row in rows:
                    identifier_cell = row.select_one('td:nth-child(1)').get_text().strip()
                    if identifier_cell == base_identifier:
                        col2 = row.select_one('td:nth-child(2)').get_text().strip()
                        col3 = row.select_one('td:nth-child(3)').get_text().strip()
                        return col2, col3

            parts = identifier.split("-")
            if len(parts) == 5:
                tabl6 = soup.find_all('table')
                for i in tabl6:
                    rowse = i.select('tbody tr')
                    parts[3] = "domain"
                    domain_identifier = "-".join(parts)

                    for row in rowse:
                        identifier_cell = row.select_one('td:nth-child(1)').get_text().strip()
                        if identifier_cell == domain_identifier:
                            col2 = row.select_one('td:nth-child(2)').get_text().strip()
                            col3 = row.select_one('td:nth-child(3)').get_text().strip()
                            return col2, col3

                    base_identifier = "-".join(identifier.split("-")[:-1])
                    for row in rows:
                        identifier_cell = row.select_one('td:nth-child(1)').get_text().strip()
                        if identifier_cell == base_identifier:
                            col2 = row.select_one('td:nth-child(2)').get_text().strip()
                            col3 = row.select_one('td:nth-child(3)').get_text().strip()
                            return col2, col3

            print(f"Identifier {identifier} not found in any of the tables.")
            return None, None
        else:
            print("Failed to retrieve data from the page.")
            return None, None

    def get_description_from_event_id(self, event_id):
        """
        Retrieves the description for a given Windows event ID.

        :param event_id: The Windows event ID to search for.
        :return: A string containing the description or an error message.
        """
        # Constants

        try:
            response = requests.get(self.ENCYCLOPEDIA_URL,timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            rows = soup.select('tr')

            for row in rows:
                identifier_cell = row.select_one('td:nth-child(2) a')
                if identifier_cell and identifier_cell.get_text().strip() == event_id:
                    description_cell = row.select_one('td:nth-child(3) a')
                    if description_cell:
                        description = description_cell.get_text().strip()
                        return description
                    else:
                        return "No status code found"

            return "Event ID not found in the page."

        except requests.RequestException as e:
            return f"Failed to retrieve data from the website: {str(e)}"
