import json
from datetime import datetime, timedelta

# Open labels.json and load the list of windows into the variable "labels".
labels_file = open("data/labeled/labels.json")
labels = json.load(labels_file)
labels_file.close()

# Read the full log into a list, one entry per line.
log_file = open("data/raw/auth_full.log")
all_lines = log_file.readlines()
log_file.close()

# We will collect the lines we keep here, as (timestamp, line) pairs.
kept_lines = []

# Go through every line in the full log, one at a time.
for line in all_lines:
    # The first word of each line is its timestamp. Turn that text into a real time value.
    first_word = line.split(" ")[0]
    ts = datetime.fromisoformat(first_word)

    # Check this line against each labeled window.
    for label in labels:
        start = datetime.fromisoformat(label["start"])
        # Labels only have whole seconds, so we extend the end by 1 second
        # to include log lines from the window's final second.
        end = datetime.fromisoformat(label["end"]) + timedelta(seconds=1)

        # ---- YOUR PART ----
        # Write the condition that is True when ts is inside this window:
        # at or after start, and strictly before end.
        if ts >= start and ts < end:
            kept_lines.append((ts, line))
            break  # stop checking windows once the line has matched one

# Sort the kept lines by timestamp, so they are in time order.
kept_lines.sort()

# Write the kept lines to the sample file.
out_file = open("data/labeled/sample_auth.log", "w")
for pair in kept_lines:
    out_file.write(pair[1])  # pair[1] is the line text; pair[0] is the timestamp
out_file.close()

print("kept", len(kept_lines), "lines")