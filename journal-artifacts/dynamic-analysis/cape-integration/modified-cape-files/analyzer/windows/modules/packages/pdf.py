# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError


class PDF(Package):
    """PDF analysis package."""

    PATHS = [
        ("ProgramFiles", "Adobe", "*a*", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Acrobat DC", "Acrobat", "Acrobat.exe"),
        ("ProgramFiles", "Microsoft", "Edge", "Application", "msedge.exe"),
        ("ProgramFiles", "Google", "Chrome", "Application", "chrome.exe"),
        ("LOCALAPPDATA", "Chromium", "Application", "chrome.exe"),
    ]
    summary = "Opens .pdf file with Adobe Reader / Acrobat, falling back to a browser if needed."
    description = """Uses AcroRd32.exe or Acrobat.exe to open a PDF file.
    Falls back to Edge or Chrome if Adobe Reader is not installed.
    The 'pdf' option is set automatically."""

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.options["pdf"] = "1"

    def start(self, path):
        # Try getting AcroRd32 or Acrobat as a backup
        try:
            reader = self.get_path_glob("AcroRd32.exe")
        except CuckooPackageError:
            try:
                reader = self.get_path_glob("Acrobat.exe")
            except CuckooPackageError:
                try:
                    reader = self.get_path("msedge.exe")
                except CuckooPackageError:
                    reader = self.get_path("chrome.exe")

        return self.execute(reader, f'"{path}"', path)
