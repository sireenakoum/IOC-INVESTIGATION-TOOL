# Pretend this is one pulse returned by OTX
pulse = {
    "name": "Lazarus Group C2",
    "adversary": "Lazarus Group",
    "tags": ["apt", "c2", "north-korea"],
    "malware_families": [
        {"display_name": "TrickBot"},
        {"display_name": "Emotet"}
    ],
    "references": ["https://example.com/report"]
}

# 1. Print the pulse name
print(pulse["name"])

# 2. Print the adversary
print(pulse.get("adversary", "Unknown"))

# 3. Print each tag using a loop
for tag in pulse["tags"]:
    print(tag)

# 4. Print each malware family using a loop
for family in pulse["malware_families"]:
    print(family["display_name"])

# 5. Print the first reference link
references = pulse.get("references", [])
if references:
    print(references[0])