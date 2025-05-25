import re
import logging
import json
from PyPDF2 import PdfReader
from tracker.models import AssessmentExtractedDetails  # adjust path as needed

logger = logging.getLogger(__name__)

# Toggle this to False to skip saving to DB during testing
SAVE_TO_MODEL = False
CREATE_JSON_OUTPUT = True

# --- Helpers ---
def safe_direct_extract(pattern, text, field_name, group_index=1, flags=re.IGNORECASE | re.MULTILINE):
    try:
        match = re.search(pattern, text, flags)
        result = match.group(group_index).strip() if match else None
        print(f"[Extracted] {field_name}: {result}")
        return result
    except Exception as e:
        logger.error(f"[Direct] Error extracting {field_name}: {e}", exc_info=False)
        return None

def clean_extracted_text(text):
    if text is None:
        return None
    text = re.sub(r"(Custom Fields:|Applicant Notes:)?", "", text)
    text = re.sub(r"\s*Compliant\s*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*\n\s*", " ", text).strip()
    return text

def safe_block_extract_raw(pattern_start_code, pattern_end_code, text, field_name, flags=re.IGNORECASE | re.DOTALL):
    try:
        start_match = re.search(pattern_start_code, text, flags)
        if not start_match:
            logger.warning(f"[Block Raw] Could not find start pattern for: {field_name}")
            return None
        start_index = start_match.end()
        end_match = re.search(pattern_end_code, text[start_index:], flags)
        end_index = start_index + end_match.start() if end_match else None
        block_text = text[start_index:end_index].strip() if end_index else text[start_index:].strip()
        print(f"[Block] {field_name}: {block_text[:200]}{'...' if len(block_text) > 200 else ''}")
        return block_text
    except Exception as e:
        logger.error(f"[Block Raw] Error extracting {field_name}: {e}", exc_info=False)
        return None

def extract_list(block):
    return [line.strip() for line in block.splitlines() if line.strip() and not line.lower().startswith("compliant")]

def extract_ce_data_from_pdf(file_path):
    extracted_data = {}
    errors = []
    try:
        reader = PdfReader(file_path)
        full_text = "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
    except Exception as e:
        logger.error(f"Error reading PDF {file_path}: {e}", exc_info=True)
        return {"errors": ["Failed to read PDF file"]}

    # --- Extraction ---
    extracted_data['validated_by'] = safe_direct_extract(r"Validated by:\s*(.*?)\n", full_text, "Validated By")
    extracted_data['certificate_number'] = safe_direct_extract(r"certificate number is\s+([a-f0-9\-]{36})", full_text, "Certificate Number")
    extracted_data['insurance_number'] = safe_direct_extract(r"insurance number is\s+(\d+)", full_text, "Insurance Number")
    extracted_data['certificate_url'] = safe_direct_extract(r"(https://registry\.blockmarktech\.com/certificates/[a-f0-9\-]+)", full_text, "Certificate URL")
    extracted_data['organisation_name'] = safe_direct_extract(r"A1\.1 Organisation Name.*?\n\n(.*?)\n", full_text, "Organisation Name")
    extracted_data['organisation_number'] = safe_direct_extract(r"A1\.3 Organisation Number.*?\n\n(\d+)", full_text, "Organisation Number")

    address_block = safe_block_extract_raw(r"A1\.4 Organisation Address.*?\n", r"A1\.5 Organisation Occupation", full_text, "Organisation Address")
    extracted_data['address_line_1'] = safe_direct_extract(r"Address Line 1:\s*(.*)", address_block, "Address Line 1")
    extracted_data['address_line_2'] = safe_direct_extract(r"Address Line 2:\s*(.*)", address_block, "Address Line 2")
    extracted_data['town_city'] = safe_direct_extract(r"Town/City:\s*(.*)", address_block, "Town/City")
    extracted_data['county'] = safe_direct_extract(r"County:\s*(.*)", address_block, "County")
    extracted_data['postcode'] = safe_direct_extract(r"Postcode:\s*(.*)", address_block, "Postcode")
    extracted_data['country'] = safe_direct_extract(r"Country:\s*(.*)", address_block, "Country")

    extracted_data['website_address'] = safe_direct_extract(r"A1\.6 Website Address.*?\n\n(https?://[\w\./-]+)", full_text, "Website Address")
    extracted_data['ce_renewal'] = bool(re.search(r"A1\.7.*?Renewal", full_text, re.IGNORECASE))
    print(f"[Extracted] CE Renewal: {extracted_data['ce_renewal']}")
    extracted_data['assessment_scope_whole_company'] = bool(re.search(r"A2\.1.*?\bYes\b", full_text, re.IGNORECASE))
    print(f"[Extracted] Scope Whole Company: {extracted_data['assessment_scope_whole_company']}")

    extracted_data['enduser_devices'] = clean_extracted_text(safe_block_extract_raw(r"A2\.4 End User Devices", r"A2\.4\.1", full_text, "End User Devices"))
    extracted_data['thin_client_devices'] = clean_extracted_text(safe_block_extract_raw(r"A2\.4\.1 Thin Client Devices", r"A2\.5", full_text, "Thin Client Devices"))
    extracted_data['server_devices'] = clean_extracted_text(safe_block_extract_raw(r"A2\.5 Server Devices", r"A2\.6", full_text, "Server Devices"))
    extracted_data['mobile_devices'] = clean_extracted_text(safe_block_extract_raw(r"A2\.6 Mobile Devices", r"A2\.7", full_text, "Mobile Devices"))
    extracted_data['networks'] = clean_extracted_text(safe_block_extract_raw(r"A2\.7 Networks", r"A2\.7\.1", full_text, "Networks"))
    extracted_data['number_of_home_workers'] = safe_direct_extract(r"A2\.7\.1 Home Workers.*?(\d+)", full_text, "Home Workers")
    extracted_data['network_equipment'] = clean_extracted_text(safe_block_extract_raw(r"A2\.8 Network Equipment", r"A2\.9", full_text, "Network Equipment"))

    cloud_block = safe_block_extract_raw(r"A2\.9 Cloud Services", r"A2\.10", full_text, "Cloud Services")
    cloud_services_list = extract_list(cloud_block)
    extracted_data['cloud_services'] = ", ".join(cloud_services_list)
    print(f"[Extracted] Cloud Services: {cloud_services_list}")

    browser_block = safe_block_extract_raw(r"A6\.2\.1 Internet Browsers", r"A6\.2\.2", full_text, "Internet Browsers")
    browser_list = extract_list(browser_block)
    extracted_data['internet_browsers'] = ", ".join(browser_list)
    print(f"[Extracted] Internet Browsers: {browser_list}")

    malware_block = safe_block_extract_raw(r"A6\.2\.2 Malware Protection", r"A6\.2\.3", full_text, "Malware Protection")
    extracted_data['malware_protection'] = clean_extracted_text(malware_block)
    print(f"[Extracted] Malware Protection: {extracted_data['malware_protection']}")

    if CREATE_JSON_OUTPUT:
        print("\n================ JSON Output ================")
        print(json.dumps(extracted_data, indent=2))

    if SAVE_TO_MODEL:
        details = AssessmentExtractedDetails(**extracted_data)
        details.save()
        logger.info("Saved extracted data to AssessmentExtractedDetails")

    return extracted_data
