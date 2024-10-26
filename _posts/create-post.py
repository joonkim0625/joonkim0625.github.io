import os
import sys
from datetime import datetime

# Template for the markdown file
TEMPLATE = """---
title: {title}
date: {date}
categories: []
tags:
  []
---
"""

# Get the current date and time in the desired format
current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S %z")

# Check if the filename is passed as an argument
if len(sys.argv) < 2:
    print("Usage: python create_md_file.py 'YYYY-MM-DD-Name-of-the-file'")
    sys.exit(1)

# Get the name of the file from the arguments
filename = sys.argv[1]

# Strip the leading date (YYYY-MM-DD-) and the .md extension from the filename
# Assumes the filename starts with a date in the format YYYY-MM-DD
file_without_date = filename[
    11:
]  # Removes the first 11 characters (the date prefix + dash)
file_base_name = os.path.splitext(file_without_date)[0]  # Removes the .md extension

# Replace hyphens with spaces for the title
title = file_base_name.replace("-", " ")

# Create the full filename with date prefix
file_date_prefix = datetime.now().strftime("%Y-%m-%d")
file_name = f"{file_date_prefix}-{file_base_name}.md"

# Create the markdown file with the template
with open(file_name, "w") as f:
    # Populate the template with the current date and formatted title
    f.write(TEMPLATE.format(title=title, date=current_date))

print(f"Created {file_name} with the template applied.")
