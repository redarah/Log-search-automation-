import subprocess
import tkinter as tk
from tkinter import ttk 
from tkinter import scrolledtext
from logAnalyzer import IPAnalyzer
from reportGenerator import ReportGenerator
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import re

class LogAnalyzer:
    def __init__(self, root):
        self.window = root
        self.window.title("Log Analyzer")
        self.window.minsize(600, 400)  # Minimum window size
        self.window.grid_rowconfigure(0, weight=0)
        self.window.grid_rowconfigure(1, weight=0)
        self.window.grid_rowconfigure(2, weight=1)
        self.window.grid_rowconfigure(3, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        self.window.grid_columnconfigure(1, weight=1)
        self.window.grid_columnconfigure(2, weight=0)
        self.create_widgets()
        self.ip_analyzer = IPAnalyzer()
    
    def create_widgets(self):
        # Header log analysis
        self.header_label = tk.Label(self.window, text="Log Analysis", font=("Arial", 24), bg="#4a90e2")
        self.header_label.grid(row=0, column=0, columnspan=3, sticky="ew")


        # Text widget for entering logs with placeholder
        self.log_entry = tk.Text(self.window, width=80, height=10, wrap=tk.WORD)
        self.log_entry.grid(row=2, column=0, columnspan=2, padx=10, pady=10)
        self.log_entry.insert(1.0, "Enter logs here...")
        self.log_entry.bind("<FocusIn>", lambda args: self.log_entry.delete('1.0', tk.END) if self.log_entry.get('1.0', tk.END).strip() == "Enter logs here..." else None)
        self.log_entry.bind("<FocusOut>", lambda args: self.log_entry.insert(1.0, "Enter logs here...") if not self.log_entry.get('1.0', tk.END).strip() else None)

        # Button to trigger log analysis
        self.analyze_button = ttk.Button(self.window, text="Logs analysis", command=self.logs_analysis)
        self.analyze_button.grid(row=2, column=2, padx=10, pady=10, sticky="n")

        # ScrolledText widget to display results
        self.result_text = scrolledtext.ScrolledText(self.window, width=80, height=10, wrap=tk.WORD)
        self.result_text.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        # Button to trigger further investigation
        self.investigate_button = ttk.Button(self.window, text="Logs Investigation", command=self.investigate_logs)
        self.investigate_button.grid(row=3, column=2, padx=10, pady=10, sticky="n")


        # Making the widgets resizable
        self.log_entry.grid(sticky="nsew")
        self.result_text.grid(sticky="nsew")


        style = ttk.Style()
        style.theme_use('clam')  # Modern looking theme

    def update_result_text(self, new_text):
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, new_text)

    def format_section(self, section_title, section_content):
        formatted_content = f"{section_title}:\n"
        for line in section_content.split('\n'):
            key_value = line.split(':')
            if len(key_value) > 1:
                formatted_content += f"\t{key_value[0]}: {key_value[1]}\n"
            else:
                formatted_content += f"\t{line}\n"
        return formatted_content

    def format_ip_analysis(self, ip_addresses):
        result_string = ""
        for ip in ip_addresses:
            result_string += f"IP: {ip}\n"
            abuseipdb_section = self.ip_analyzer.search_ip(ip, 'abuseipdb')
            virustotal_section = self.ip_analyzer.search_ip(ip, 'virustotal')
            iplocation_section = self.ip_analyzer.search_ip(ip, 'iplocation')
            result_string += self.format_section("Abuse idp", abuseipdb_section)
            result_string += self.format_section("Virus Total", virustotal_section)
            result_string += self.format_section("IP Location", iplocation_section)
            result_string += "\n"
        return result_string

    def format_event_analysis(self, event_info):
        result_string = ""
        for event_id, status_codes in event_info.items():
            description = self.ip_analyzer.get_description_from_event_id(event_id)
            if description != "Event ID not found in the page.":
                result_string += f"\nTesting Event ID: {event_id}\n"
                result_string += f"Event ID Description: {description}\n"
                for status_code in status_codes:
                    result_string += f"Testing Status Code: {status_code}\n"
                    result_string += self.ip_analyzer.search_windows_code_status(event_id, status_code)
        return result_string

    def format_sid_analysis(self, sids):
        result_string = ""
        printed_values = set()
        for sid in sids:
            col2, col3 = self.ip_analyzer.extract_info_from_table(sid)
            if col2 is not None and col3 is not None:
                if (col2, col3) not in printed_values:
                    result_string += f"\nSID: {sid}\n"
                    result_string += f"Display Name: {col2}\n"
                    result_string += f"Description: {col3}\n"
                    printed_values.add((col2, col3))
            else:
                result_string += "Sid Not found"
        return result_string
   
    def logs_analysis(self):
        log = self.log_entry.get("1.0", tk.END)
        ip_addresses, event_info, sids, num_events = self.ip_analyzer.extract_info_from_log(log)
        result_string = self.format_ip_analysis(ip_addresses)
        result_string += self.format_event_analysis(event_info)
        result_string += self.format_sid_analysis(sids)
        result_string += f"\nEvents: {num_events}\n"
        self.update_result_text(result_string)

##### Investigate Logs #####

    def evaluate_abuseip(self,abuse_info):
        attributes = ["Confidence Score", "Total Reports", "Is Whitelisted"]
        values = {attr: None for attr in attributes}

        for attr in attributes:
            match = re.search(rf"{attr}:\s*(.+)", abuse_info)
            if match:
                values[attr] = int(match.group(1)) if attr != "Is Whitelisted" else bool(match.group(1))

        if all(value is not None for value in values.values()):
            confidence_score, total_reports, is_whitelisted = values.values()
            if not is_whitelisted and ((total_reports <= 30 and confidence_score <= 10) or confidence_score > 50):
                return "❌\n"
            elif total_reports < 30 and total_reports >= 60 and confidence_score < 11 and confidence_score >= 50:
                return "✴️\n"
            elif confidence_score >= 90:
                return "❌\n"
            elif confidence_score >= 70:
                return "✴️\n"
            elif is_whitelisted or total_reports <= 5:
                return "✔️\n"
            else:
                return "❌\n"
        else:
            return "no result"

    def evaluate_virustotal(self,vt_info):
        attributes = ["Harmless", "Malicious", "Suspicious"]
        values = {attr: None for attr in attributes}

        for attr in attributes:
            match = re.search(rf"{attr}:\s*(\d+)", vt_info)
            if match:
                values[attr] = int(match.group(1))

        if all(value is not None for value in values.values()):
            if values["Malicious"] > 0:
                return "❌\n"
            elif values["Suspicious"] > 0:
                return "✴️\n"
            else:
                return "✔️\n"
        else:
            return "no result"

    def evaluate_checker(self,ip_location_info, abuse_info):
        abuse_isp = None
        abuse_country = None
        ip_location = None
        ip_isp = None
        location_1_match = re.search(r"Country Code:\s*(.+)", abuse_info)
        if location_1_match:
            abuse_country = str(location_1_match.group(1))

        isp_1_match = re.search(r"ISP:\s*(.+)", abuse_info)
        if isp_1_match:
            abuse_isp = str(isp_1_match.group(1))

        location_2_match = re.search(r"Country Code:\s*(.+)", ip_location_info)
        if location_2_match:
            ip_location = str(location_2_match.group(1)) 

        isp_2_match = re.search(r"ISP:\s*(.+)", ip_location_info)
        if isp_2_match:
            ip_isp = str(isp_2_match.group(1)) 

        if abuse_isp is not None and abuse_country is not None and ip_location is not None and ip_isp is not None:
            if abuse_isp == ip_isp and abuse_country == ip_location:
                return "✔️\n"
            elif ip_isp =='-' or ip_location== '-' or abuse_isp =="None" or abuse_country=="None":
                return '✴️\n'
            else:
                return "❌\n"
        else:
            return "No result"

    def evaluate_combined(self,emoji_abuseip, emoji_virustotal, emoji_checker):
        emojis = [emoji_abuseip, emoji_virustotal, emoji_checker]
        if all(emoji == "✔️\n" for emoji in emojis):
            return "✔️\n"
        elif any(emoji == "❌\n" for emoji in emojis):
            return "❌\n"
        elif any(emoji == "✴️\n" for emoji in emojis):
            return "✴️\n"
        else:
            return "No result\n"


    def get_windows_info(self,event_info,sids,num_events):
        windows_info = ""
        for event_id, status_codes in event_info.items():
            description = self.ip_analyzer.get_description_from_event_id(event_id)
        
            if description != "Event ID not found in the page." and description !="No status code found":
                windows_info += f"Testing Event ID: {event_id}\n"
                windows_info += f"Event ID Description: {description}\n"
                for status_code in status_codes:
                    windows_info += f"Testing Status Code: {status_code}\n"
                    windows_info += self.ip_analyzer.search_windows_code_status(event_id, status_code)
                
        
        printed_values = set()
        for sid in sids:
            col2, col3 = self.ip_analyzer.extract_info_from_table(sid)
            if col2 is not None and col3 is not None:
                if (col2, col3) not in printed_values:
                    windows_info += f"\nSID: {sid}\n"
                    windows_info += f"Display Name: {col2}\n"
                    windows_info += f"Description: {col3}\n"
                    
                    printed_values.add((col2, col3))
            else:
                windows_info += "Sid Not found"
                
                
        
        return windows_info
    
    def open_investigate_window(self):
        # Investigate Logs Window
        self.investigate_window = tk.Toplevel(self.window)
        self.investigate_window.title("Logs Investigation")
        self.investigate_window.resizable(True, True)  # Allow horizontal and vertical resizing
        self.investigate_window.minsize(1400, 650)

        # Create a canvas to hold all content
        canvas = tk.Canvas(self.investigate_window)
        canvas.pack(side="left", fill="both", expand=True)

        # Create a scrollbar and connect it to the canvas
        scrollbar = tk.Scrollbar(self.investigate_window, command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Create a frame inside the canvas
        content_frame = tk.Frame(canvas)
        canvas.create_window((0, 0), window=content_frame, anchor="nw")

        # Add a pretty header with a title
        header_frame = tk.Frame(content_frame, bg="#424242")  # Dark grey header background
        header_label = tk.Label(header_frame, text="Investigate Logs", font=("Helvetica", 18), fg="white", bg="#424242")
        header_label.pack(padx=10, pady=10)
        header_frame.grid(row=0, column=0, columnspan=2, sticky="nsew")

        # Main frames with padding and background color
        left_frame = tk.Frame(content_frame, padx=20, pady=20, bg="#f0f0f0")  # Light grey background
        right_frame = tk.Frame(content_frame, padx=20, pady=20, bg="#f0f0f0")  # Light grey background
        left_frame.grid(row=1, column=0, sticky="nsew")
        right_frame.grid(row=1, column=1, sticky="nsew")

        # Attach the canvas to the scrollbar and configure scrolling
        content_frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))

        # Details table
        self.details_table = tk.Frame(left_frame)
        self.details_table.pack(side="top", fill="x", expand=True)
        self.row_index = 1  # Initialize variable to keep track of the row index

        # Add the column headers
        headers = ["IP Address", "AbuseIP", "VirusTotal", "IP Location", "Location Check", "Final Status"]
        for col, header in enumerate(headers):
            label = tk.Label(self.details_table, text=header, font=("Helvetica", 12), padx=10, pady=5, relief=tk.RIDGE, bg="#f0f0f0")
            label.grid(row=0, column=col, sticky="ew")
        # Pie Chart
        values = [20, 30, 50]  # Pie chart values
        labels = ["Label 1", "Label 2", "Label 3"]  # Labels for the pie chart
        colors = ['#4CAF50', '#FFC107', '#F44336']  # Green, Gold, Red

        pie_chart_figure = plt.figure(figsize=(3, 3), facecolor='none')  # Increase the size if needed, with a transparent background
        ax = pie_chart_figure.add_subplot(1, 1, 1)
        wedges, texts, autotexts = ax.pie(values, labels=[label if value > 0 else "" for label, value in zip(labels, values)],
                                            autopct=lambda p: '{:.0f}%'.format(p) if p > 0 else '',
                                            textprops=dict(color="black"),  # Changed text color to black
                                            colors=colors)

        # Style adjustments
        plt.rcParams['font.family'] = 'Segoe UI Emoji'

        plt.setp(autotexts, size=10, weight="bold")
        plt.title("Your Pie Chart Title")  # Set your desired title
        plt.legend(wedges, labels, loc="upper center", bbox_to_anchor=(0.5, -0.1))  # Adjust the legend position to be lower

        self.pie_chart_canvas = FigureCanvasTkAgg(pie_chart_figure, master=right_frame)
        self.pie_chart_canvas.draw()
        self.pie_chart_canvas.get_tk_widget().pack(side="top", pady=10)


        # Windows Information
        self.windows_info_label = tk.Label(left_frame, text="Windows Information:")
        self.windows_info_label.pack(side="top", anchor="w")
        self.windows_info_text = tk.Text(left_frame, width=40, height=10)
        self.windows_info_text.pack(side="top", fill="x", expand=True)


        # General Overview and IP Info
        self.general_info_label = tk.Label(right_frame, text="General Overview:", font=("Helvetica", 12), bg="#f0f0f0")
        self.general_info_label.pack(side="top", anchor="w", padx=20, pady=5)
        self.general_overview_label = ttk.Label(right_frame, text="Threat Percentage: 0%", font=("Helvetica", 10))
        self.general_overview_label.pack(side="top", anchor="w", padx=20, pady=2)

        separator = ttk.Separator(right_frame, orient="horizontal")  # Separator line for visual separation
        separator.pack(side="top", fill="x", padx=20, pady=5)

        self.ip_info_label = tk.Label(right_frame, text="IP Addresses and Final Status:", font=("Helvetica", 14), bg="#f0f0f0")  # Corrected the label text
        self.ip_info_label.pack(side="top", anchor="w", padx=20, pady=5)
        self.ip_info_text = tk.Text(right_frame, width=40, height=8, font=("Helvetica", 12), wrap="word", relief="flat", borderwidth=2)
        self.ip_info_text.pack(side="top", fill="x", expand=True, padx=20, pady=5)

        # Generate the Report Section
        self.choose_template_label = tk.Label(right_frame, text="Choose a template:", font=("Helvetica", 10), bg="#f0f0f0")
        self.choose_template_label.pack(side="top", anchor="w", padx=20, pady=10)

        template_choices = ["Template 1",
                            "Template 2",
                            "Template 3"]

        self.template_combobox = ttk.Combobox(right_frame, values=template_choices, width=50)
        self.template_combobox.pack(side="top", anchor="w", padx=20, pady=5)
        self.template_combobox.set("Choose a template")

        generate_button = tk.Button(right_frame, text="Generate Report", command=self.generate_report,
                                    font=("Helvetica", 10, 'bold'), fg="white", bg="#007BFF", activebackground="#0056b3",
                                    relief="flat", padx=15, pady=5)
        generate_button.pack(side="top", anchor="w", padx=20, pady=10)

    def fill_grid(self, log):
        ip_addresses, event_info, sids, num_events = self.ip_analyzer.extract_info_from_log(log)
        emoji_counts = {'✔️': 0, '✴️': 0, '❌': 0}  # Added this line to keep track of emoji counts

        for ip in ip_addresses:
            abuse_result = self.ip_analyzer.search_ip(ip, 'abuseipdb')
            vt_result = self.ip_analyzer.search_ip(ip, 'virustotal')
            ip_loc_result = self.ip_analyzer.search_ip(ip, 'iplocation')

            emoji_abuseip = self.evaluate_abuseip(abuse_result)
            emoji_virustotal = self.evaluate_virustotal(vt_result)
            emoji_checker = self.evaluate_checker(ip_loc_result, abuse_result)
            emoji_combined = self.evaluate_combined(emoji_abuseip, emoji_virustotal, emoji_checker).strip()

            row_data = [
                ip,
                f"{emoji_abuseip} {abuse_result}",
                f"{emoji_virustotal} {vt_result}",
                ip_loc_result,
                emoji_checker,
                emoji_combined
            ]

            row_color_mapping = {'✔️': 'green', '✴️': 'yellow', '❌': 'red'}
            row_color = row_color_mapping.get(emoji_combined, 'white')
            row_color = 'white' 

            # Create and place Labels with the information
            for col, data in enumerate(row_data):
                label = tk.Label(self.details_table, text=data, padx=10, pady=5)
                label.grid(row=self.row_index, column=col, sticky="ew")


            self.row_index += 1

            # Increment the emoji count
            emoji_counts[emoji_combined] += 1  # Added this line to increment the count for each emoji

        # Call the method to update the Pie Chart with the new data if necessary
        self.update_pie_chart(emoji_counts)  # Ensure this line uses the correct emoji_counts

    def update_pie_chart(self, emoji_counts):
        labels = ['✔️ Secure', '✴️ Potential Risk', '❌ Critical Threat']
        sizes = [emoji_counts['✔️'], emoji_counts['✴️'], emoji_counts['❌']]
        colors = ['#4CAF50', '#FFC107', '#F44336']  # green, gold, red

        # Remove zero values and corresponding labels
        sizes, labels = zip(*[(size, label) for size, label in zip(sizes, labels) if size > 0])

        self.pie_chart_canvas.figure.clf()  # Clear the existing figure
        self.pie_chart_canvas.figure.patch.set_visible(False)  # Transparent background for figure
        ax = self.pie_chart_canvas.figure.add_subplot(111, frame_on=False)  # No frame
        wedges, texts, autotexts = ax.pie(sizes,
                                        autopct=lambda p: '{:.1f}%'.format(p) if p > 0 else '',
                                        textprops=dict(color="black"),  # Set text color to black or any desired color
                                        colors=colors)

        # Style adjustments
        plt.rcParams['font.family'] = 'Segoe UI Emoji'  # Font with good emoji support
        plt.setp(autotexts, size=10, weight="bold")
        plt.title('Threat Distribution')  # Set your desired title

        # Add a legend to display labels and colors, and adjust its position
        plt.legend(wedges, labels, loc="lower right")

        # Equal aspect ratio ensures that pie is drawn as a circle.
        ax.axis('equal')

        # Refresh the canvas
        self.pie_chart_canvas.draw()

    def investigate_logs(self):
        self.open_investigate_window()
        log = self.log_entry.get("1.0", tk.END)
        self.log=log
        self.ip_addresses, self.event_info, self.sids, self.num_events = self.ip_analyzer.extract_info_from_log(self.log)
        
        #self.fill_treeview(log)
        self.fill_grid(log)
        self.update_overview_percentage()
        self.extract_ip_and_emojis()
        self.update_ip_info()
        self.update_windows_info()

    def update_overview_percentage(self):
        status_points = {
            '✔️': 0,
            '✴️': 0.5,
            '❌': 1,
        }

        total_points = 0
        total_entries = 0
        for row in range(1, self.row_index):  # Start from the second row
            label = self.details_table.grid_slaves(row=row, column=5)[0]
            emoji_combined = label.cget('text').strip()
            total_points += status_points.get(emoji_combined, 0)
            total_entries += 1
                
        overview_percentage = (total_points / total_entries) * 100 if total_entries != 0 else 0
        self.general_overview_label.config(text=f"Threat Percentage: {overview_percentage:.2f}%")

    def extract_ip_and_emojis(self):
        self.ip_addresses = []
        self.emoji_combined_list = []

        for row in range(1,self.row_index): # Assuming self.row_index has the number of rows
            ip_label = self.details_table.grid_slaves(row=row, column=0)[0] # Accessing the label at the first column
            emoji_label = self.details_table.grid_slaves(row=row, column=5)[0] # Accessing the label at the sixth column

            ip = ip_label.cget("text")
            emoji_combined = emoji_label.cget("text").strip()

            self.ip_addresses.append(ip)
            self.emoji_combined_list.append(emoji_combined)

        # Your further code, if any

    def update_ip_info(self):
        self.ip_info_text.config(height=len(self.ip_addresses))
        for ip, emoji_combined in zip(self.ip_addresses, self.emoji_combined_list):
            ip_info = f"IP Address: {ip} - Final Status: {emoji_combined}\n"
            self.ip_info_text.insert(tk.END, ip_info)

    def update_windows_info(self):
        windows_info = self.get_windows_info(self.event_info, self.sids, self.num_events)
        self.windows_info_text.insert(tk.END, windows_info)

    def generate_report(self):
        template_choice = self.template_combobox.get()
        report_generator = ReportGenerator(self.ip_analyzer)
        report_generator.select_and_generate_template(template_choice, self.log, self.event_info, self.sids, self.num_events)

if __name__ == "__main__" and 1:
    root = tk.Tk()
    app = LogAnalyzer(root)
    root.mainloop()
