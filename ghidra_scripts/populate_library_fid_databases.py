# Create one FID database per library described by a TSV file.
# @category FunctionID
# @runtime PyGhidra

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from ghidra.feature.fid.db import FidFileManager
from ghidra.feature.fid.service import FidService
from ghidra.program.database import ProgramContentHandler
from ghidra.program.model.lang import LanguageID
from java.io import File
from java.util import ArrayList

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *


def find_programs(folder) -> list:
    programs = []
    for domain_file in folder.getFiles():
        monitor.checkCancelled()
        if domain_file.getContentType() == ProgramContentHandler.PROGRAM_CONTENT_TYPE:
            programs.append(domain_file)
    for child in folder.getFolders():
        programs.extend(find_programs(child))
    return programs


def java_program_list(programs: list) -> ArrayList:
    result = ArrayList()
    for program in sorted(programs, key=lambda item: str(item.getPathname())):
        result.add(program)
    return result


def main() -> None:
    args = list(getScriptArgs())
    if len(args) != 3:
        raise ValueError(
            "usage: populate_library_fid_databases "
            "<libraries.tsv> <language-id> <report.jsonl>"
        )

    rows_path = Path(args[0])
    language_id = LanguageID(args[1])
    report_path = Path(args[2])
    manager = FidFileManager.getInstance()
    service = FidService()

    with (
        rows_path.open(encoding="utf-8") as rows,
        report_path.open("w", encoding="utf-8") as report,
    ):
        for raw_line in rows:
            line = raw_line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) != 5:
                raise ValueError(f"invalid library row: {line}")

            library, version, variant, folder_path, fidb_path_text = fields
            folder = state.getProject().getProjectData().getFolder(folder_path)
            fidb_path = Path(fidb_path_text)
            if folder is None:
                raise ValueError(f"missing project folder: {folder_path}")
            if fidb_path.exists():
                raise FileExistsError(f"refusing to overwrite: {fidb_path}")

            programs = java_program_list(find_programs(folder))
            if programs.isEmpty():
                raise ValueError(f"no programs in: {folder_path}")

            java_fidb_path = File(str(fidb_path))
            manager.createNewFidDatabase(java_fidb_path)
            fid_file = manager.addUserFidFile(java_fidb_path)
            fid_file.setActive(True)
            fid_db = fid_file.getFidDB(True)
            try:
                result = service.createNewLibraryFromPrograms(
                    fid_db,
                    library,
                    version,
                    variant,
                    programs,
                    None,
                    language_id,
                    None,
                    None,
                    monitor,
                )
                fid_db.saveDatabase("FIDB PoC deterministic population", monitor)
                population = {
                    "library": library,
                    "version": version,
                    "variant": variant,
                    "fidb_path": str(fidb_path.resolve()),
                    "program_count": programs.size(),
                    "attempted": result.getTotalAttempted(),
                    "added": result.getTotalAdded(),
                    "excluded": result.getTotalExcluded(),
                }
                report.write(json.dumps(population, sort_keys=True) + "\n")
                report.flush()
            finally:
                fid_db.close()


main()
