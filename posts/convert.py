import os
import re

import toml
import yaml


def yaml_to_toml(yaml_dict):
    # Remove Jekyll-specific fields
    yaml_dict.pop("layout", None)
    yaml_dict.pop("categories", None)
    yaml_dict["draft"] = False

    # Format date to ISO 8601 with T and proper timezone
    if "date" in yaml_dict and isinstance(yaml_dict["date"], str):
        match = re.match(
            r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}) ?([+-]\d{2}:?\d{2})?",
            yaml_dict["date"],
        )
        if match:
            date_str = match.group(1)
            time_str = match.group(2)
            tz_str = match.group(3) or ""
            if tz_str and len(tz_str) == 5:
                tz_str = tz_str[:3] + ":" + tz_str[3:]
            yaml_dict["date"] = f"{date_str}T{time_str}{tz_str}"
        else:
            yaml_dict["date"] = yaml_dict["date"].replace(" ", "T", 1)

    # Ensure tags is always a list
    if "tags" in yaml_dict and isinstance(yaml_dict["tags"], str):
        yaml_dict["tags"] = [tag.strip() for tag in yaml_dict["tags"].split(",")]

    return toml.dumps(yaml_dict)


for filename in os.listdir("."):
    if filename.endswith(".md") and os.path.isfile(filename):
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()

        # Extract YAML front matter
        match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
        if not match:
            print(f"Skipping {filename}: no YAML front matter found.")
            continue

        front_matter = yaml.safe_load(match.group(1))
        body = match.group(2)

        toml_front = yaml_to_toml(front_matter)

        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"+++\n{toml_front}+++\n\n{body}")

        print(f"Converted: {filename}")

print("All done!")
