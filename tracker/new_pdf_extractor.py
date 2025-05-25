import fitz  # PyMuPDF
import re
import json

# Load PDF
doc = fitz.open("lateraltechnologyltd-2024-07-10-08-14-11.pdf")
text = "\n".join(page.get_text() for page in doc)

# Utility function
def extract_between(start, end="Compliant", multiline=False):
    pattern = rf"{re.escape(start)}(.*?){re.escape(end)}"
    flags = re.DOTALL if multiline else 0
    match = re.search(pattern, text, flags)
    return match.group(1).strip() if match else None

# Dynamic extraction logic
def extract_list_block(label):
    block = extract_between(label, "Compliant", multiline=True)
    if block:
        return [line.strip("-•* ").strip() for line in block.splitlines() if line.strip()]
    return []

def extract_value(label, pattern):
    block = extract_between(label, "Compliant", multiline=True)
    if not block:
        return None
    match = re.search(pattern, block)
    return match.group(1).strip() if match else block.strip()

# JSON structure
data = {
    "Validated_by": extract_between("Validated by:", "Thank you"),
    "Certificate_Number": re.search(r"certificate number is ([a-f0-9\-]+)", text).group(1),
    "Insurance_Number": re.search(r"insurance number is (\d+)", text).group(1),
    "Certificate_URL": re.search(r"(https://registry\.blockmarktech\.com/certificates/[a-f0-9\-]+)", text).group(1),
    "Organisation_Name": extract_between("A1.1 Organisation Name", "Compliant"),
    "Organisation_Number": extract_between("A1.3 Organisation Number", "Compliant"),
    "Organisational_Address": {
        "Address_Line_1": extract_between("Address Line 1:", "Address Line 2:"),
        "Address_Line_2": extract_between("Address Line 2:", "Town/City:"),
        "Town_City": extract_between("Town/City:", "County:"),
        "County": extract_between("County:", "Postcode:"),
        "Postcode": extract_between("Postcode:", "Country:"),
        "Country": extract_between("Country:", "A1.5")
    },
    "Website_Address": extract_between("A1.6 Website Address", "Compliant"),
    "CE_Renewal": "Yes" if "Renewal" in extract_between("A1.7", "Compliant") else "No",
    "Assessment_Scope_Whole_Company": "Yes" if "Yes" in extract_between("A2.1", "Compliant") else "No",
    "Enduser_Devices": extract_between("A2.4 End User Devices", "Compliant", multiline=True),
    "Thin_Client_Devices": extract_between("A2.4.1 Thin Client Devices", "Compliant"),
    "Server_Devices": extract_between("A2.5 Server Devices", "Compliant", multiline=True),
    "Mobile_Devices": extract_between("A2.6 Mobile Devices", "Compliant", multiline=True),
    "Networks": extract_between("A2.7 Networks", "Compliant", multiline=True),
    "Number_of_Home_Workers": extract_value("A2.7.1 Home Workers", r"(\d+)"),
    "Network_Equipment": extract_between("A2.8 Network Equipment", "Compliant", multiline=True),
    "Cloud_Services": extract_list_block("A2.9 Cloud Services"),
    "Internet_Browsers": extract_list_block("A6.2.1 Internet Browsers"),
    "Malware_Protection": extract_between("A6.2.2 Malware Protection", "Compliant")
}

# Output
print(json.dumps(data, indent=2))
