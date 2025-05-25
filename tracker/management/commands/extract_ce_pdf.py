from django.core.management.base import BaseCommand
from tracker.pdf_file_extractor_v2 import extract_ce_data_from_pdf
import os

class Command(BaseCommand):
    help = "Extracts CE assessment data from a PDF and optionally saves to the database"

    def add_arguments(self, parser):
        parser.add_argument("pdf_path", type=str, help="Path to the CE PDF file")
        parser.add_argument("--save", action="store_true", help="Save extracted data to the database")
        parser.add_argument("--json", action="store_true", help="Print extracted data as JSON")

    def handle(self, *args, **options):
        pdf_path = options["pdf_path"]

        if not os.path.exists(pdf_path):
            self.stderr.write(self.style.ERROR(f"File does not exist: {pdf_path}"))
            return

        # Set runtime toggles
        from tracker import pdf_extractor
        pdf_extractor.SAVE_TO_MODEL = options["save"]
        pdf_extractor.CREATE_JSON_OUTPUT = options["json"]

        self.stdout.write(self.style.SUCCESS(f"Processing: {pdf_path}"))
        result = extract_ce_data_from_pdf(pdf_path)

        if "errors" in result:
            self.stderr.write(self.style.WARNING(f"Extraction completed with warnings: {len(result['errors'])}"))
        else:
            self.stdout.write(self.style.SUCCESS("Extraction successful."))