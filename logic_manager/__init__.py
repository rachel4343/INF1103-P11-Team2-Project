# The __init__.py file helps Python recognise that this folder is a package containing related Python modules.
# A special file used to initialise a package and optionally expose its classes/functions for easier imports.
from .audit_trail import add_audit_entry, get_audit_trail
from .statistics import generate_statistics

# Keep your existing exports here too so nothing breaks
from .logic_manager import *