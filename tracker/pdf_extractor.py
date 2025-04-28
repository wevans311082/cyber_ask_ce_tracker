# tracker/pdf_extractor.py
import re
from PyPDF2 import PdfReader
import logging
import io

logger = logging.getLogger(__name__)

# --- Helpers (Keep safe_direct_extract, clean_extracted_text, safe_block_extract_raw as is) ---
def safe_direct_extract(pattern, text, field_name, group_index=1, flags=re.IGNORECASE | re.MULTILINE):
    # (Implementation from previous step)
    try:
        match = re.search(pattern, text, flags)
        if match: return match.group(group_index).strip()
        else: logger.warning(f"[Direct] Could not find pattern for: {field_name}"); return None
    except Exception as e: logger.error(f"[Direct] Error extracting {field_name}: {e}", exc_info=False); return None

def clean_extracted_text(text, question_code=None):
    # (Implementation from previous step)
    if text is None: return None
    patterns_to_remove = [ r"Please Note.*?\.", ]
    cleaned = text
    for pattern in patterns_to_remove: cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE | re.DOTALL).strip()
    cleaned = re.sub(r"\s*Compliant\s*$", "", cleaned, flags=re.IGNORECASE | re.MULTILINE).strip()
    cleaned = re.sub(r"^(Custom Fields:|Applicant Notes:)\s*", "", cleaned, flags=re.IGNORECASE | re.MULTILINE).strip()
    cleaned = re.sub(r'\s*\n\s*', ' ', cleaned).strip()
    cleaned = re.sub(r'\s{2,}', ' ', cleaned).strip()
    return cleaned if cleaned else None

def safe_block_extract_raw(pattern_start_code, pattern_end_code, text, field_name, flags=re.IGNORECASE | re.DOTALL):
    # (Implementation from previous step)
    block_text = None
    try:
        start_match = re.search(pattern_start_code, text, flags)
        if not start_match: logger.warning(f"[Block Raw] Could not find start pattern '{pattern_start_code}' for: {field_name}"); return None
        start_index = start_match.end()
        end_match = re.search(pattern_end_code, text[start_index:], flags | re.MULTILINE) # Add MULTILINE here too
        if not end_match: end_match = re.search(r"\nA[1-8]\.\d", text[start_index:], re.MULTILINE) # Fallback to next Q
        if end_match: end_index = start_index + end_match.start()
        else: end_index = None; logger.warning(f"[Block Raw] Could not find reliable end marker after '{pattern_start_code}' for {field_name}.")
        block_text = text[start_index:end_index].strip()
        return block_text if block_text else None
    except Exception as e: logger.error(f"[Block Raw] Error extracting raw block {field_name}: {e}", exc_info=False); return None


# --- Main Extraction Function ---
def extract_ce_data_from_pdf(file_path):
    extracted_data = {}
    errors = []
    full_text = ""

    # (Keep PDF reading logic)
    try:
        reader = PdfReader(file_path); full_text = "".join(page.extract_text() + "\n" for page in reader.pages if page.extract_text())
        if not full_text: errors.append("Could not extract any text from the PDF."); extracted_data['errors'] = errors; return extracted_data
    except Exception as e: logger.error(f"Error reading PDF {file_path}: {e}", exc_info=True); errors.append(f"Failed to read PDF file: {e}"); extracted_data['errors'] = errors; return extracted_data

    # --- Extraction Attempts ---

    # (Keep all previously working fields as they were)
    extracted_data['report_date'] = safe_direct_extract(r"Report date:\s*(\d{1,2}/\d{1,2}/\d{4})", full_text, "Report Date", flags=re.IGNORECASE)
    if extracted_data['report_date'] is None: errors.append("Report Date not found.")
    extracted_data['certificate_number'] = safe_direct_extract(r"certificate number is\s+([a-f0-9\-]{36})\b", full_text, "Certificate Number", flags=re.IGNORECASE)
    if extracted_data['certificate_number'] is None: errors.append("Certificate Number not found.")
    extracted_data['certificate_url'] = safe_direct_extract(r"(https://registry\.blockmarktech\.com/certificates/[a-f0-9\-]+)/?\b", full_text, "Certificate URL", flags=re.IGNORECASE)
    if extracted_data['certificate_url'] is None: errors.append("Certificate URL not found.")
    org_name_block = safe_block_extract_raw(r"A1\.1 Organisation Name", r"\nA1\.2", full_text, "Organisation Name Block")
    if org_name_block: name_match = re.search(r"\b([A-Z][A-Z\s]*?(?:\sLTD|\sLIMITED)?)\b", org_name_block); extracted_data['organization_name'] = name_match.group(1).strip() if name_match else None
    if not extracted_data.get('organization_name'): errors.append("Organisation Name (A1.1) not found or pattern failed."); extracted_data['organization_name'] = None
    org_num_block_raw = safe_block_extract_raw(r"A1\.3 Organisation Number", r"\nA1\.4", full_text, "Organisation Number Block")
    if org_num_block_raw: num_match = re.search(r"\b(\d{8})\b", org_num_block_raw); extracted_data['organization_number'] = num_match.group(1) if num_match else None
    if not extracted_data.get('organization_number'): errors.append("Organisation Number (A1.3) not found."); extracted_data['organization_number'] = None
    addr_block_raw = safe_block_extract_raw(r"A1\.4 Organisation Address", r"\nA1\.5", full_text, "Organisation Address Block")
    if addr_block_raw:
        addr_block_cleaned = re.sub(r".*registered address for your organisation.*?\?", "", addr_block_raw, flags=re.IGNORECASE | re.DOTALL).strip()
        addr_block_cleaned = re.sub(r"^(Custom Fields:|Address Line 1:|Address Line 2:|Town/City:|County:|Postcode:|Country:)\s*", "", addr_block_cleaned, flags=re.IGNORECASE | re.MULTILINE).strip()
        address_match = re.search(r"\bUK\b(.*?)Compliant", addr_block_cleaned, re.IGNORECASE | re.DOTALL)
        if address_match: address_text = address_match.group(1).strip(); extracted_data['organization_address'] = re.sub(r'[\s\n]+', ', ', address_text).strip(', ')
        else: errors.append("Organisation Address (A1.4) block found but couldn't isolate address lines."); extracted_data['organization_address'] = None
    else: extracted_data['organization_address'] = None; errors.append("Organisation Address (A1.4) block not found.")
    website_block = safe_block_extract_raw(r"A1\.6 Website Address", r"\nA1\.7", full_text, "Website Address Block")
    if website_block: url_match = re.search(r"(https?://[^\s,]+)", website_block); extracted_data['website_address'] = url_match.group(1) if url_match else None
    if not extracted_data.get('website_address'): errors.append("Website Address (A1.6) not found."); extracted_data['website_address'] = None
    scope_block = safe_block_extract_raw(r"A2\.1 Assessment Scope", r"\nA2\.3", full_text, "Assessment Scope Block")
    if scope_block:
        if re.search(r"\bYes\b", scope_block, re.IGNORECASE): extracted_data['assessment_scope'] = "Whole Organisation"
        elif re.search(r"\bNo\b", scope_block, re.IGNORECASE): extracted_data['assessment_scope'] = "Sub-Set"
        else: errors.append("Assessment Scope (A2.1) block found but couldn't determine Yes/No."); extracted_data['assessment_scope'] = None
    else: extracted_data['assessment_scope'] = None; errors.append("Assessment Scope (A2.1) block not found.")
    geo_block_raw = safe_block_extract_raw(r"A2\.3 Geographical Location", r"\nA2\.4", full_text, "Geographical Location Block")
    if geo_block_raw:
        instruction_end_pattern = re.escape("retail stores).").replace(r"\ ", r"\s*"); end_marker = re.search(instruction_end_pattern, geo_block_raw, re.IGNORECASE | re.DOTALL)
        if end_marker: start_of_answer_index = end_marker.end(); answer_text_raw = geo_block_raw[start_of_answer_index:].strip(); extracted_data['geographical_location'] = clean_extracted_text(answer_text_raw)
        else: logger.warning("Could not find instruction end marker '...retail stores).' in Geo Location block."); extracted_data['geographical_location'] = clean_extracted_text(geo_block_raw)
    if not extracted_data.get('geographical_location'): errors.append("Geographical Location (A2.3) not found or empty after cleaning."); extracted_data['geographical_location'] = None
    hw_block = safe_block_extract_raw(r"A2\.7\.1 Home Workers", r"\nA2\.8", full_text, "Home Workers Block")
    if hw_block: num_match = re.search(r"(\d+)", hw_block); extracted_data['home_workers'] = num_match.group(1) if num_match else None
    if not extracted_data.get('home_workers'): errors.append("Number of Home Workers (A2.7.1) not found."); extracted_data['home_workers'] = None


    # --- Fields to Fix (A2.4, A2.4.1, A2.5, A2.6, A2.7, A2.8, A2.9) ---

    # End User Devices (A2.4)
    eud_block_raw = safe_block_extract_raw(r"A2\.4 End User Devices", r"\nA2\.4\.1", full_text, "End User Devices Block")
    if eud_block_raw:
        instruction_end_pattern = re.escape("technical information.").replace(r"\ ", r"\s*")
        end_marker = re.search(instruction_end_pattern, eud_block_raw, re.IGNORECASE | re.DOTALL)
        if end_marker: answer_text_raw = eud_block_raw[end_marker.end():].strip()
        else: logger.warning("Could not find instruction end marker '...technical information.' in EUD block."); answer_text_raw = eud_block_raw # Fallback
        extracted_data['end_user_devices'] = clean_extracted_text(answer_text_raw)
    if not extracted_data.get('end_user_devices'): errors.append("End User Devices (A2.4) not found or empty after cleaning."); extracted_data['end_user_devices'] = None

    # Thin Client Devices (A2.4.1)
    thin_block_raw = safe_block_extract_raw(r"A2\.4\.1 Thin Client Devices", r"\nA2\.5", full_text, "Thin Client Devices Block")
    if thin_block_raw:
        instruction_end_pattern = re.escape("v3-1-January-2023.pdf").replace(r"\ ", r"\s*") # End is the PDF link
        end_marker = re.search(instruction_end_pattern, thin_block_raw, re.IGNORECASE | re.DOTALL)
        if end_marker: answer_text_raw = thin_block_raw[end_marker.end():].strip()
        else: logger.warning("Could not find instruction end marker '...pdf' in Thin Client block."); answer_text_raw = thin_block_raw # Fallback
        extracted_data['thin_client_devices'] = clean_extracted_text(answer_text_raw)
    if not extracted_data.get('thin_client_devices'): errors.append("Thin Client Devices (A2.4.1) not found or empty after cleaning."); extracted_data['thin_client_devices'] = None

    # Server Devices (A2.5)
    server_block_raw = safe_block_extract_raw(r"A2\.5 Server Devices", r"\nA2\.6", full_text, "Server Devices Block")
    if server_block_raw:
        instruction_end_pattern = re.escape("Linux 8.3").replace(r"\ ", r"\s*") # End is example
        end_marker = re.search(instruction_end_pattern, server_block_raw, re.IGNORECASE | re.DOTALL)
        if end_marker: answer_text_raw = server_block_raw[end_marker.end():].strip()
        else: logger.warning("Could not find instruction end marker '...Linux 8.3' in Server block."); answer_text_raw = server_block_raw # Fallback
        extracted_data['server_devices'] = clean_extracted_text(answer_text_raw)
    if not extracted_data.get('server_devices'): errors.append("Server Devices (A2.5) not found or empty after cleaning."); extracted_data['server_devices'] = None

    # Mobile Devices (A2.6)
    mobile_block_raw = safe_block_extract_raw(r"A2\.6 Mobile Devices", r"\nA2\.7", full_text, "Mobile Devices Block")
    if mobile_block_raw:
        instruction_end_pattern = re.escape("technical information.").replace(r"\ ", r"\s*") # Same end as EUD
        end_marker = re.search(instruction_end_pattern, mobile_block_raw, re.IGNORECASE | re.DOTALL)
        if end_marker: answer_text_raw = mobile_block_raw[end_marker.end():].strip()
        else: logger.warning("Could not find instruction end marker '...technical information.' in Mobile block."); answer_text_raw = mobile_block_raw # Fallback
        extracted_data['mobile_devices'] = clean_extracted_text(answer_text_raw)
    if not extracted_data.get('mobile_devices'): errors.append("Mobile Devices (A2.6) not found or empty after cleaning."); extracted_data['mobile_devices'] = None

    # Networks (A2.7)
    network_block_raw = safe_block_extract_raw(r"A2\.7 Networks", r"\nA2\.7\.1", full_text, "Networks Block")
    if network_block_raw:
        instruction_end_pattern = re.escape("v3-1-January-2023.pdf").replace(r"\ ", r"\s*") # End is the PDF link
        end_marker = re.search(instruction_end_pattern, network_block_raw, re.IGNORECASE | re.DOTALL)
        if end_marker: answer_text_raw = network_block_raw[end_marker.end():].strip()
        else: logger.warning("Could not find instruction end marker '...pdf' in Network block."); answer_text_raw = network_block_raw # Fallback
        extracted_data['networks'] = clean_extracted_text(answer_text_raw)
    if not extracted_data.get('networks'): errors.append("Networks (A2.7) not found or empty after cleaning."); extracted_data['networks'] = None

    # Network Equipment (A2.8)
    equip_block_raw = safe_block_extract_raw(r"A2\.8 Network Equipment", r"\nA2\.9", full_text, "Network Equipment Block")
    if equip_block_raw:
        instruction_end_pattern = re.escape("serial numbers.").replace(r"\ ", r"\s*") # End of instructions
        end_marker = re.search(instruction_end_pattern, equip_block_raw, re.IGNORECASE | re.DOTALL)
        if end_marker: answer_text_raw = equip_block_raw[end_marker.end():].strip()
        else: logger.warning("Could not find instruction end marker '...serial numbers.' in Equip block."); answer_text_raw = equip_block_raw # Fallback
        extracted_data['network_equipment'] = clean_extracted_text(answer_text_raw)
    if not extracted_data.get('network_equipment'): errors.append("Network Equipment (A2.8) not found or empty after cleaning."); extracted_data['network_equipment'] = None

    # Cloud Services (A2.9)
    cloud_block_raw = safe_block_extract_raw(r"A2\.9 Cloud Services", r"\nA2\.10", full_text, "Cloud Services Block")
    if cloud_block_raw:
        instruction_end_pattern = re.escape("v3-1-January-2023.pdf").replace(r"\ ", r"\s*") # End is the PDF link
        end_marker = re.search(instruction_end_pattern, cloud_block_raw, re.IGNORECASE | re.DOTALL)
        if end_marker: answer_text_raw = cloud_block_raw[end_marker.end():].strip()
        else: logger.warning("Could not find instruction end marker '...pdf' in Cloud block."); answer_text_raw = cloud_block_raw # Fallback
        extracted_data['cloud_services'] = clean_extracted_text(answer_text_raw)
    if not extracted_data.get('cloud_services'): errors.append("Cloud Services (A2.9) not found or empty after cleaning."); extracted_data['cloud_services'] = None


    # --- Finalize ---
    extracted_data['errors'] = errors
    logger.info(f"Extraction attempt for {file_path} completed. Errors: {len(errors)}")
    return extracted_data