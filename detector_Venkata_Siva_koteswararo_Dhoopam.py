import csv
import re
import sys
import spacy

nlp = spacy.load("en_core_web_sm")

# Regex patterns for standalone PII
patterns = {
    "phone": re.compile(r"\b\d{10}\b"),
    "aadhaar": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "passport": re.compile(r"\b[A-Z]{1}\d{7}\b"),
    "upi": re.compile(r"\b[\w\.\-]+@[\w]+\b")
}

# Redaction logic
def redact_field(value):
    value = patterns["phone"].sub(lambda m: m.group(0)[:2] + "XXXXX" + m.group(0)[-3:], value)
    for key in ["aadhaar", "passport", "upi"]:
        value = patterns[key].sub("[REDACTED_PII]", value)
    return value

# Combinatorial PII detection
def is_combinatorial_pii(text):
    doc = nlp(text)
    has_name = any(ent.label_ == "PERSON" for ent in doc.ents)
    has_email = re.search(r"\b[\w\.-]+@[\w\.-]+\.\w{2,4}\b", text)
    has_address = any(ent.label_ in ["GPE", "LOC", "FAC"] for ent in doc.ents)
    return sum([has_name, has_email, has_address]) >= 2

# Main processing
def process_csv(input_file, output_file):
    with open(input_file, newline='', encoding='utf-8') as infile, open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames + ['is_pii']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            row_text = ' '.join(row.values())
            standalone_match = any(p.search(row_text) for p in patterns.values())
            combinatorial_match = is_combinatorial_pii(row_text)
            is_pii = standalone_match or combinatorial_match
            row['is_pii'] = str(is_pii)

            if is_pii:
                for key in row:
                    row[key] = redact_field(row[key])
            writer.writerow(row)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_venkata.py iscp_pii_dataset.csv")
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = "redacted_output_venkata.csv"
    process_csv(input_file, output_file)
