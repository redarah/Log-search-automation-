
import subprocess
import re

class ReportGenerator:
    """
    ReportGenerator is responsible for generating incident reports based on
    provided log information, event details, and selected templates.
    
    Attributes:
        ip_analyzer: An optional object for analyzing IP information.
    """
    
    def __init__(self, ip_analyzer=None):
        """
        Initializes the ReportGenerator with an optional IP analyzer.
        
        Args:
            ip_analyzer: An optional object for analyzing IP information.
        """
        self.ip_analyzer = ip_analyzer
        pass

  

    def select_and_generate_template(self, template_choice, log, event_info, sids, num_events):
        """
        Selects and generates a report template based on provided details.

        Args:
            template_choice: The selected template.
            log: The log information.
            event_info: Details of the events.
            sids: Security Identifier (SID) information.
            num_events: Number of events.
        """
        
        windows_info = self.json_windows_info(event_info, sids, num_events)
        generated_template = self.report_template(template_choice, windows_info)

        with open("incident.txt", "w") as file:
            file.write(generated_template)
            print("\nGenerated Template saved to incident.txt")

        try:
            subprocess.run(["notepad.exe", "incident.txt"], check=True)
        except subprocess.CalledProcessError:
            print("Error opening the text editor.")





    def json_windows_info(self, event_info, sids, num_events):
        """
        Creates a JSON structure for Windows event and SID information.

        Args:
            event_info: Event information.
            sids: Security Identifier (SID) information.
            num_events: Number of events.
        
        Returns:
            A dictionary containing Windows event and SID information.
        """
        
        windows_info = {
            'event_id': [],
            'event_description': [],
            'status_code': [],
            'status_code_description': [],
            'sid': [],
            'sid_description': []
        }

        for event_id, status_codes in event_info.items():
            description = self.ip_analyzer.get_description_from_event_id(event_id)

            if description != "Event ID not found in the page." :
                windows_info['event_id'].append(event_id)
                windows_info['event_description'].append(description)
            
                for status_code in status_codes:
                    windows_info['status_code'].append(status_code)
                    windows_info['status_code_description'].append(self.ip_analyzer.search_windows_code_status(event_id, status_code))

        printed_values = set()
        for sid in sids:
            col2, col3 = self.ip_analyzer.extract_info_from_table(sid)
            if col2 is not None and col3 is not None:
                if (col2, col3) not in printed_values:
                    windows_info['sid'].append(sid)
                    windows_info['sid_description'].append(col2 + " - " + col3)
                
                    printed_values.add((col2, col3))
            else:
                windows_info['sid'].append(sid)
                windows_info['sid_description'].append("Sid Not found")

        return windows_info

    def generate_report(self, template_choice, log, event_info, sids, num_events):
        
        """
        Generates a report if a template is chosen.

        Args:
            template_choice: The selected template.
            log: The log information.
            event_info: Details of the events.
            sids: Security Identifier (SID) information.
            num_events: Number of events.
        
        Returns:
            A message string if no report was chosen, else None.
        """
        
        if template_choice:
            self.select_and_generate_template(template_choice, log, event_info, sids, num_events)
        else:
            return "No report was chosen"
     
    def report_template(self,template_choice, placeholders):

        """
        Defines the report template structure.

        Args:
            template_choice: The selected template.
            placeholders: A dictionary of placeholders and their values.
        
        Returns:
            The formatted report template as a string.
        """  
        test = ''.join([f'Status Code: {code}\nDescription: {desc if desc else "N/A"}\n' for code, desc in zip(placeholders.get('status_code', ''), placeholders.get('status_code_description', '')) if desc  ])
        if template_choice == "Template 1":
            return f"""

Dear {placeholders.get('recipient_name', '')},

We have detected unusual activity on your network that requires your immediate attention.

Event Details:
- Windows Event ID: {placeholders.get('event_id', '')[0] }
- Description : {placeholders.get('event_description', '')[0] }
- Status Code information :
{test}
- SID :{placeholders.get('sid', '')[0] }
- SID description : {placeholders.get('sid_description', '')[0] }
- Please see the links for more details.

Recommendation:
- Investigate the source of this activity.
- Implement additional security measures to prevent future incidents.
- Consult your IT security team for assistance.

Links : 
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={placeholders['event_id'][0]}
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-{placeholders['event_id'][0]}

If you have any questions or need further assistance, please contact us.

Best regards,
Your Name"""
            
        elif template_choice == "Template 2":
            return f"""

Attention Name ,

We are writing to inform you about a recent security event on your network.

Incident Details:
- Windows Event ID: {placeholders.get('event_id', '')[0] }
- Description : {placeholders.get('event_description', '')[0] }
- Status Code information :
{test}
- SID :{placeholders.get('sid', '')[0] }
- SID description : {placeholders.get('sid_description', '')[0] }
- Please see the links for more details.

Action Required:
- Review the incident details and take appropriate action.
- Analyze the potential impact on your network.
- Enhance security measures to prevent similar incidents.

Links : 
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={placeholders['event_id'][0]}
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-{placeholders['event_id'][0]}

For more information or assistance, please don't hesitate to reach out.

Sincerely,
Your Name"""
        elif template_choice == "Template 3":
            return f"""

Hello {placeholders.get('recipient_name', '')},

We have identified a security anomaly that needs your immediate attention.

Incident Report:
- Windows Event ID: {placeholders.get('event_id', '')[0] }
- Description : {placeholders.get('event_description', '')[0] }
- Status Code information :
{test}
- SID :{placeholders.get('sid', '')[0] }
- SID description : {placeholders.get('sid_description', '')[0] }
- Please see the links for more details.


Recommended Steps:
- Investigate the incident further to understand the scope.
- Implement necessary security controls to prevent recurrence.
- Collaborate with your IT team for a thorough assessment.

Links : 
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={placeholders['event_id'][0]}
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-{placeholders['event_id'][0]}

Should you require any assistance, please feel free to contact us.

Best regards,
Your Name"""
        else:
            return "Invalid template number."